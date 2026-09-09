use std::error::Error;

use sysinfo::System;

use protocol::Metrics;

pub struct Context {
    pub sys: System,
}

impl Context {
    pub fn new() -> Self {
        Self {
            sys: System::new_all(),
        }
    }
}

pub trait Collector {
    fn name(&self) -> &'static str;

    fn collect_into(
        &mut self,
        ctx: &mut Context,
        metrics: &mut Metrics,
    ) -> Result<(), Box<dyn Error>>;
}
