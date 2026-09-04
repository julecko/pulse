mod user;

use std::ffi::OsString;
use std::process::ExitCode;

fn app() -> pulse_cli::App {
    pulse_cli::App {
        name: "server",
        unit: "pulse-server",
        daemon: "/usr/lib/pulse/pulse-serverd",
        role: pulse_cli::Role::Server,
        service_user: Some("pulse"),
        extra_subcommand: Some((
            "user",
            "Manage API accounts (add/list/passwd/rm; run `user --help`)",
        )),
    }
}

fn main() -> ExitCode {
    // `pulse-server user ...` is handled here (needs the server crate + SQLite);
    // everything else goes to the shared config/control front-end.
    let mut argv = std::env::args_os();
    let _bin = argv.next();
    if argv.next().as_deref() == Some(OsString::from("user").as_os_str()) {
        return user::run(app(), std::env::args_os().skip(2).collect());
    }
    pulse_cli::run::<pulse_server::Config>(app())
}
