//! Manual rotation check:  cargo run -p pulse-shared --example rotate
//!
//! Writes a line every 5s to ./logs/rotate.log with minutely rotation, keeping
//! 3 files. Watch `./logs/` — after a minute you get rotate.<date-with-minute>.log
//! and the oldest is pruned once there are more than 3.

use std::path::PathBuf;
use std::thread::sleep;
use std::time::Duration;

use pulse_shared::LogConfig;

fn main() {
    let cfg = LogConfig {
        file: Some(PathBuf::from("logs/rotate.log")),
        rotation: "minutely".to_string(),
        keep_files: 3,
        level: "info".to_string(),
        ansi: false,
    };

    let _guard = pulse_shared::init("rotate", &cfg).expect("log init");

    for i in 0.. {
        tracing::info!(i, "tick");
        sleep(Duration::from_secs(5));
    }
}
