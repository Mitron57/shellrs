use crate::gethostname::gethostname;
use nix::libc;
use nix::sys::signal;
use nix::sys::signal::Signal;
use nix::sys::wait::WaitStatus;
use nix::unistd::{close, dup2, fork, pipe, ForkResult};
use signal_hook::{
    consts::{SIGINT, SIGTERM},
    iterator::Signals,
};
use std::collections::VecDeque;
use std::error::Error;
use std::ffi::c_int;
use std::fs::OpenOptions;
use std::io::{stdin, stdout, ErrorKind, Stdin, Stdout, Write};
use std::os::fd::{IntoRawFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::CommandExt;
use std::process::Command;
use std::slice::Iter;
use std::sync::mpsc::{channel, Receiver};
use std::time::Duration;

#[derive(Debug)]
pub struct Shell {
    username: String,
    hostname: String,
    home: String,
    working_directory: String,
    stdin: Stdin,
    stdout: Stdout,
    exit_status: i32,
    input: String,
    shotgun: Receiver<c_int>,
}

impl Shell {
    pub fn new() -> Shell {
        let (sender, shotgun) = channel();
        std::thread::spawn(move || {
            let mut signals = Signals::new([SIGINT, SIGTERM]).unwrap();
            for signal in signals.forever() {
                sender.send(signal).unwrap();
            }
        });
        Self {
            username: std::env::var("USER").unwrap(),
            #[cfg(target_os = "macos")]
            hostname: gethostname().replace(".local", ""),
            #[cfg(target_os = "linux")]
            hostname: gethostname().trim().to_owned(),
            home: std::env::var("HOME").unwrap(),
            working_directory: std::env::current_dir()
                .unwrap()
                .to_str()
                .unwrap()
                .to_string(),
            stdin: stdin(),
            stdout: stdout(),
            exit_status: 0,
            input: String::new(),
            shotgun,
        }
    }

    fn parse_path(&self, path: &str) -> String {
        if path.is_empty() {
            return path.to_string();
        }
        let split: Vec<&str> = path.split('/').collect();
        let mut path_stack = VecDeque::with_capacity(split.len());
        let mut parsed: VecDeque<&str> = if path.starts_with('/') {
            VecDeque::new()
        } else {
            self.working_directory
                .split('/')
                .filter(|&part| !part.is_empty())
                .collect()
        };
        for part in split {
            if part.is_empty() {
                continue;
            }
            path_stack.push_back(part);
        }
        while let Some(part) = path_stack.pop_front() {
            match part {
                "." => continue,
                ".." => {
                    parsed.pop_back();
                }
                _ => {
                    parsed.push_back(part);
                }
            }
        }
        let parsed = parsed.into_iter().collect::<Vec<_>>().join("/");
        format!("/{parsed}")
    }

    fn interpolate_env_variable(&self, variable: &str) -> Option<String> {
        if variable.starts_with('$') {
            let interpolated = variable.strip_prefix('$').unwrap_or_default();
            if interpolated == "?" {
                return Some(self.exit_status.to_string());
            }
            Some(std::env::var(interpolated).unwrap_or_default())
        } else {
            None
        }
    }

    fn parse_io(
        &self,
        arg: &str,
        next: &str,
        descriptors: &mut (Option<RawFd>, Option<RawFd>),
    ) -> Result<(), Box<dyn Error>> {
        match arg {
            ">" => {
                let file = std::fs::File::create(next)?;
                descriptors.1 = Some(file.into_raw_fd());
            }
            ">>" => {
                let file = OpenOptions::new()
                    .create(true)
                    .truncate(false)
                    .append(true)
                    .open(next)?;
                descriptors.1 = Some(file.into_raw_fd());
            }
            "<" => {
                let file = std::fs::File::open(next)?;
                descriptors.0 = Some(file.into_raw_fd());
            }
            _ => unreachable!(),
        }
        Ok(())
    }

    fn parse_quotes(&self, arg: &str, args_iter: &mut Iter<String>, args: &mut Vec<String>) {
        let mut arg = arg.strip_prefix('"').unwrap().to_owned();
        if arg.ends_with('"') {
            arg = arg.strip_suffix('"').unwrap().to_owned();
        } else {
            for part in args_iter {
                let mut part = part.to_string();
                if part.ends_with('"') {
                    part = part.strip_suffix('"').unwrap().to_owned();
                }
                part = self.interpolate_env_variable(&part).unwrap_or(part);
                arg.push_str(&format!(" {part}"));
            }
        }
        args.push(arg);
    }

    fn parse_backslashes(&self, part: &str, args_iter: &mut Iter<String>, args: &mut Vec<String>) {
        let mut combined = part.strip_suffix('\\').unwrap().to_owned();
        if let Some(arg) = args_iter.next() {
            let arg = self.interpolate_env_variable(arg).unwrap_or_default();
            combined.push_str(&format!(" {arg}"));
        }
        args.push(combined);
    }

    fn parse_envs(&self, arg: &str) -> String {
        match arg.split_once('$') {
            Some((before, after)) => {
                let after = "$".to_owned() + after;
                before.to_owned() + &self.interpolate_env_variable(&after).unwrap_or(after)
            }
            None => arg.to_owned(),
        }
    }

    fn parse_input(&self, input: &str) -> Result<(String, Vec<String>), Box<dyn Error>> {
        if input.is_empty() {
            return Ok((String::new(), Vec::new()));
        }

        let parts: Vec<String> = input.split_whitespace().map(str::to_owned).collect();
        let (cmd, args) = parts.split_first().unwrap();

        let mut args_iter = args.iter();
        let mut args = Vec::with_capacity(args.len());

        while let Some(part) = args_iter.next() {
            let part = self.parse_envs(part);
            if part.starts_with('"') {
                self.parse_quotes(&part, &mut args_iter, &mut args);
            } else if part.ends_with('\\') {
                self.parse_backslashes(&part, &mut args_iter, &mut args);
            } else {
                let part = part.to_owned();
                match part.split_once('*') {
                    Some((before, after)) => {
                        let opendir = match std::fs::read_dir(&self.working_directory) {
                            Ok(dir) => dir,
                            Err(err) => {
                                return Err(err.into());
                            }
                        };
                        for entry in opendir {
                            let entry = if let Ok(entry) = entry {
                                entry
                            } else {
                                continue;
                            };
                            let filename = entry.file_name();
                            let name = filename.as_bytes();
                            if name.starts_with(before.as_bytes())
                                && name.ends_with(after.as_bytes())
                            {
                                args.push(String::from_utf8_lossy(name).to_string());
                            }
                        }
                    }
                    None => args.push(part),
                };
            }
        }
        Ok((cmd.clone(), args))
    }

    fn exec_child(&mut self, command: &str, args: &[String]) -> ! {
        let err = Command::new(command)
            .args(args)
            .current_dir(&self.working_directory)
            .exec();
        println!("{command}: {err}");
        std::process::exit(127)
    }

    fn launch_command(
        &mut self,
        command: &str,
        args: &[String],
        fds: (Option<RawFd>, Option<RawFd>),
    ) -> Result<(), Box<dyn Error>> {
        let fork = unsafe { fork() };
        match fork {
            Ok(ForkResult::Parent { child }) => loop {
                if let Ok(signal) = self.shotgun.recv_timeout(Duration::from_millis(10)) {
                    signal::kill(child, Some(Signal::try_from(signal)?))?;
                }
                match nix::sys::wait::waitpid(child, Some(nix::sys::wait::WaitPidFlag::WNOHANG))? {
                    WaitStatus::Exited(_, code) => {
                        self.exit_status = code;
                        break Ok(());
                    }
                    WaitStatus::Signaled(_, signal, _) => {
                        self.exit_status = signal as i32;
                        break Ok(());
                    }
                    _ => {
                        continue;
                    }
                }
            },
            Ok(ForkResult::Child) => {
                if let Some(read) = fds.0 {
                    dup2(read, libc::STDIN_FILENO)?;
                    close(read)?;
                }
                if let Some(write) = fds.1 {
                    dup2(write, libc::STDOUT_FILENO)?;
                    close(write)?;
                }
                self.exec_child(command, args)
            }
            Err(_) => Err("fork failed".into()),
        }
    }

    fn launch_command_piped(
        &mut self,
        commands: Vec<(String, Vec<String>)>,
    ) -> Result<(), Box<dyn Error>> {
        let mut prev_pipe: Option<(_, _)> = None;
        for (i, (command, args)) in commands.iter().enumerate() {
            let pipe = if i < commands.len() - 1 {
                let (read, write) = pipe()?;
                Some((read.into_raw_fd(), write.into_raw_fd()))
            } else {
                None
            };
            let fds = match (prev_pipe, pipe) {
                (Some(prev), Some(next)) => (Some(prev.0), Some(next.1)),
                (Some(prev), None) => (Some(prev.0), None),
                (None, Some(next)) => (None, Some(next.1)),
                _ => (None, None),
            };
            self.launch_command(command, args, fds)?;
            if let Some(read) = fds.0 {
                close(read)?;
            }
            if let Some(write) = fds.1 {
                close(write)?;
            }
            prev_pipe = pipe;
        }
        Ok(())
    }

    fn cd(&mut self, args: &mut [String]) -> Result<(), Box<dyn Error>> {
        if args.is_empty() {
            self.working_directory = self.home.clone();
            self.exit_status = 0;
            return Ok(());
        }
        let path = self.parse_path(&args[0]);
        let os_path = std::path::Path::new(&path);
        if os_path.exists() && os_path.is_dir() {
            self.working_directory = path;
            self.exit_status = 0;
            return Ok(());
        }
        self.exit_status = 1;
        if !os_path.exists() {
            return Err(format!("cd: no such file or directory: {}", path).into());
        }
        Err(format!("cd: not a directory: {}", path).into())
    }

    fn execute(&mut self, cmd: &str, args: &mut [String]) -> Result<(), Box<dyn Error>> {
        match cmd {
            "cd" => self.cd(args),
            "pwd" => {
                println!("{}", self.working_directory);
                Ok(())
            }
            _ => {
                let mut descriptors = (None, None);
                let mut parsed = Vec::with_capacity(args.len());
                let mut args_iter = args.iter().peekable();
                while let Some(arg) = args_iter.next() {
                    if arg == ">" || arg == ">>" || arg == "<" {
                        let next = match args_iter.next() {
                            Some(next) => next,
                            None => return Err(format!("parse error near {arg}").into()),
                        };
                        self.parse_io(arg, next, &mut descriptors)?;
                        continue;
                    }
                    parsed.push(arg.clone());
                }
                self.launch_command(cmd, &parsed, descriptors)?;
                Ok(())
            }
        }
    }

    fn show_working_directory(&mut self) {
        let wd = self.working_directory.replace(&self.home, "~");
        print!("{}@{} {} % ", self.username, self.hostname, wd);
        self.stdout.flush().unwrap();
    }

    fn batch_execute(&mut self) {
        let input: Vec<String> = self
            .input
            .split("&&")
            .map(str::to_owned)
            .filter(|part| !part.is_empty())
            .collect();
        for shard in input {
            if shard.contains("|") {
                self.pipe_execute(&shard);
                if self.exit_status != 0 {
                    break;
                }
                continue;
            }
            let (cmd, mut args) = match self.parse_input(shard.trim()) {
                Ok(command_line) => command_line,
                Err(err) => {
                    eprintln!("Error: {err}");
                    continue;
                }
            };
            if cmd == "exec" {
                self.input = self.input.replace("exec ", "");
                let (cmd, args) = match self.parse_input(&self.input) {
                    Ok(command_line) => command_line,
                    Err(err) => {
                        eprintln!("Error: {err}");
                        continue;
                    }
                };
                let _ = Command::new(cmd)
                    .args(args)
                    .current_dir(&self.working_directory)
                    .exec();
            }
            if let Err(err) = self.execute(&cmd, &mut args) {
                eprintln!("Error: {err}");
            }
            if self.exit_status != 0 {
                break;
            }
        }
        self.input.clear();
    }

    fn pipe_execute(&mut self, shard: &str) {
        let commands: Vec<_> = shard
            .split("|")
            .map(|part| {
                self.parse_input(part).unwrap_or_else(|err| {
                    eprintln!("Error: {err}");
                    (String::new(), Vec::new())
                })
            })
            .filter(|(cmd, _)| !cmd.is_empty())
            .collect();
        if let Err(err) = self.launch_command_piped(commands) {
            eprintln!("Error: {err}");
        }
    }

    pub fn listen_to_stdin(&mut self) {
        loop {
            self.show_working_directory();
            if let Err(e) = self.stdin.read_line(&mut self.input) {
                if e.kind() == ErrorKind::UnexpectedEof {
                    return;
                }
            }
            self.input = self.input.trim().to_string();
            if self.input.is_empty() {
                continue;
            }
            if self.input == "exit" {
                return;
            }
            self.batch_execute();
            self.input.clear();
        }
    }
}
