use sysinfo::System;

use protocol::HostInfo;

pub fn info() -> HostInfo {
    HostInfo {
        hostname: System::host_name().unwrap_or_else(|| "unknown".to_string()),
        os: System::name(),
        os_version: System::os_version(),
        kernel_version: System::kernel_version(),
    }
}
