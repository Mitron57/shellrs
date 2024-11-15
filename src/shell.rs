use crate::gethostname::gethostname;
use nix::libc;
use nix::sys::signal;
use nix::sys::signal::Signal;
use nix::sys::wait::WaitStatus;
use nix::unistd::{close, dup2, fork, ForkResult};
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
use std::sync::mpsc::{channel, Receiver};
use std::time::Duration;

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
            hostname: gethostname(),
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
        let mut path_stack = VecDeque::new();
        let mut parsed: VecDeque<&str> = if path.starts_with('/') {
            VecDeque::new()
        } else {
            self.working_directory
                .split('/')
                .filter(|&part| !part.is_empty())
                .collect()
        };
        for part in path.split('/') {
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

    fn parse_input(&self, input: &str) -> Result<(String, Vec<String>), Box<dyn Error>> {
        if input.is_empty() {
            return Ok((String::new(), Vec::new()));
        }
        let parts: Vec<String> = input.split_whitespace().map(str::to_owned).collect();
        let (cmd, args) = parts.split_first().unwrap();
        let mut args_iter = args.iter();
        let mut args = Vec::with_capacity(args.len());
        while let Some(part) = args_iter.next() {
            let part = match part.split_once('$') {
                Some((before, after)) => {
                    let after = "$".to_owned() + after;
                    before.to_owned() + &self.interpolate_env_variable(&after).unwrap_or(after)
                }
                None => part.to_owned(),
            };
            if part.starts_with('"') {
                let mut arg = part.strip_prefix('"').unwrap().to_owned();
                if arg.ends_with('"') {
                    arg = arg.strip_suffix('"').unwrap().to_owned();
                } else {
                    for part in args_iter.by_ref() {
                        let mut part = part.to_string();
                        if part.ends_with('"') {
                            part = part.strip_suffix('"').unwrap().to_owned();
                        }
                        part = self.interpolate_env_variable(&part).unwrap_or(part);
                        arg.push_str(&format!(" {part}"));
                    }
                }
                args.push(arg);
            } else if part.ends_with('\\') {
                let mut combined = part.strip_suffix('\\').unwrap().to_owned();
                if let Some(arg) = args_iter.next() {
                    let arg = self.interpolate_env_variable(arg).unwrap_or_default();
                    combined.push_str(&format!(" {arg}"));
                }
                args.push(combined);
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

    fn launch_command(
        &mut self,
        command: &str,
        args: &[String],
        other_input: (Option<RawFd>, Option<RawFd>),
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
                match other_input {
                    (Some(input), Some(output)) => {
                        close(libc::STDIN_FILENO)?;
                        close(libc::STDOUT_FILENO)?;
                        dup2(input, libc::STDIN_FILENO)?;
                        dup2(output, libc::STDOUT_FILENO)?;
                    }
                    (Some(input), None) => {
                        close(libc::STDIN_FILENO)?;
                        dup2(input, libc::STDIN_FILENO)?;
                    }
                    (None, Some(output)) => {
                        close(libc::STDOUT_FILENO)?;
                        dup2(output, libc::STDOUT_FILENO)?;
                    }
                    _ => {}
                }
                let err = Command::new(command)
                    .args(args)
                    .current_dir(&self.working_directory)
                    .exec();
                let _ = self
                    .stdout
                    .write(format!("{}: {}\n", command, err).as_bytes());
                std::process::exit(127)
            }
            Err(_) => Err("fork failed".into()),
        }
    }

    fn launch_command_piped(
        &mut self,
        commands: Vec<(String, Vec<String>)>,
    ) -> Result<(), Box<dyn Error>> {
        let mut prev_pipe = None;
        for (i, (command, args)) in commands.iter().enumerate() {
            let pipe = if i < commands.len() - 1 {
                let (read, write) = nix::unistd::pipe()?;
                Some((read.into_raw_fd(), write.into_raw_fd()))
            } else {
                None
            };
            let fork = unsafe { fork() };
            match fork {
                Ok(ForkResult::Parent { child }) => {
                    loop {
                        if let Ok(signal) = self.shotgun.recv_timeout(Duration::from_millis(10)) {
                            signal::kill(child, Some(Signal::try_from(signal)?))?;
                            self.exit_status = signal;
                            if let Some((read, write)) = prev_pipe {
                                close(read)?;
                                close(write)?;
                            }
                            if let Some((read, write)) = pipe {
                                close(read)?;
                                close(write)?;
                            }
                            return Ok(());
                        }
                        match nix::sys::wait::waitpid(
                            child,
                            Some(nix::sys::wait::WaitPidFlag::WNOHANG),
                        )? {
                            WaitStatus::Exited(_, code) => {
                                self.exit_status = code;
                                break;
                            }
                            WaitStatus::Signaled(_, signal, _) => {
                                self.exit_status = signal as i32;
                                break;
                            }
                            _ => continue,
                        }
                    }
                    if let Some((read, _)) = prev_pipe {
                        close(read)?;
                    }
                    if let Some((_, write)) = pipe {
                        close(write)?;
                    }
                    prev_pipe = pipe;
                }
                Ok(ForkResult::Child) => {
                    if let Some((read, _)) = prev_pipe {
                        dup2(read, libc::STDIN_FILENO)?;
                        close(read)?;
                    }
                    if let Some((_, write)) = pipe {
                        dup2(write, libc::STDOUT_FILENO)?;
                        close(write)?;
                    }
                    let err = Command::new(command)
                        .args(args)
                        .current_dir(&self.working_directory)
                        .exec();
                    let _ = self
                        .stdout
                        .write(format!("{}: {}\n", command, err).as_bytes());
                    std::process::exit(127);
                }
                Err(e) => return Err(e.into()),
            }
        }
        Ok(())
    }

    fn operate_command(&mut self, cmd: &str, args: &mut [String]) -> Result<(), Box<dyn Error>> {
        match cmd {
            "cd" => {
                let path_idx = args
                    .iter()
                    .position(|arg| !arg.starts_with('-'))
                    .unwrap_or(args.len());
                if let Some(path) = args.get_mut(path_idx) {
                    *path = self.parse_path(path);
                }
                match self.launch_command(cmd, args, (None, None)) {
                    Ok(_) => {
                        if self.exit_status == 0 {
                            self.working_directory = if path_idx == args.len() {
                                self.home.clone()
                            } else {
                                args[path_idx].clone()
                            }
                        }
                        Ok(())
                    }
                    Err(error) => Err(error),
                }
            }
            "pwd" => {
                println!("{}", self.working_directory);
                Ok(())
            }
            _ => {
                let mut descriptors = (None, None);
                let mut parsed = Vec::with_capacity(args.len());
                let mut args_iter = args.iter().peekable();
                while let Some(arg) = args_iter.next() {
                    let next = if arg == ">" || arg == ">>" || arg == "<" {
                        match args_iter.next() {
                            Some(next) => next,
                            None => {
                                return Err(format!("parse error near {arg}").into());
                            }
                        }
                    } else {
                        &String::new()
                    };
                    if arg == ">" {
                        let file = std::fs::File::create(next)?;
                        descriptors.1 = Some(file.into_raw_fd());
                    } else if arg == ">>" {
                        let file = OpenOptions::new()
                            .create(true)
                            .truncate(false)
                            .append(true)
                            .open(next)?;
                        descriptors.1 = Some(file.into_raw_fd());
                    } else if arg == "<" {
                        let file = std::fs::File::open(next)?;
                        descriptors.0 = Some(file.into_raw_fd());
                    } else {
                        parsed.push(arg.to_string());
                    }
                }
                self.launch_command(cmd, &parsed, descriptors)?;
                Ok(())
            }
        }
    }

    pub fn listen_to_stdin(&mut self) {
        loop {
            let wd = self.working_directory.replace(&self.home, "~");
            print!("{}@{} {} % ", self.username, self.hostname, wd);
            self.stdout.flush().unwrap();
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
            let input: Vec<_> = self.input.split("&&").map(str::to_owned).collect();
            for shard in input {
                if shard.contains('|') {
                    let commands: Vec<_> = self
                        .input
                        .split('|')
                        .map(|part| {
                            self.parse_input(part.trim()).unwrap_or_else(|err| {
                                eprintln!("Error: {err}");
                                (String::new(), Vec::new())
                            })
                        })
                        .filter(|(cmd, _)| !cmd.is_empty())
                        .collect();
                    if let Err(e) = self.launch_command_piped(commands) {
                        eprintln!("Error: {}", e);
                    }
                    self.input.clear();
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
                    Command::new(cmd)
                        .args(args)
                        .current_dir(&self.working_directory)
                        .exec();
                }
                if let Err(err) = self.operate_command(&cmd, &mut args) {
                    eprintln!("Error: {err}");
                }
            }
            self.input.clear();
        }
    }
}
