use crate::shell::Shell;
mod shell;
mod gethostname;

fn main() {
    Shell::new().listen_to_stdin()
}
