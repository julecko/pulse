mod alerts;
mod auth;
mod metrics;
mod pairing;
mod text;
mod user;

pub use alerts::{
    AlertMetric, AlertOperator, AlertRecord, AlertRule, AlertSeverity, NewAlertRule, PushDevice,
    PushPlatform, RegisterPushDevice, UpdateAlertRule,
};
pub use auth::{AuthEvent, AuthEventKind, AuthEventRecord};
pub use metrics::{CpuInfo, DiskInfo, HostInfo, LinuxInfo, MemoryInfo, Metrics, MetricsRecord};
pub use pairing::{
    AGENT_SECRET_LEN, AgentSummary, PairRequest, PairResponse, PairingStatus, SetPairingRequest,
    agent_fingerprint, is_valid_agent_secret,
};
pub use text::{escape_for_display, is_unsafe_display_char};
pub use user::{LoginRequest, LoginResponse, MAX_USERNAME_LEN, UserInfo, is_valid_username};
