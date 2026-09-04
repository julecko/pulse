# Pulse Android Integration Guide

This document describes the current Pulse server and the contract an Android
application should implement against it. It is based on the Rust source in this
repository; do not assume that an endpoint exists unless it is listed here.

## System overview

Pulse has two daemons and two operator CLIs:

```text
pulse-agentd  -- MessagePack over TCP/TLS -->  pulse-serverd
     |                                             |
     |                                             +-- SQLite history
     |                                             +-- HTTP JSON API
     |                                             +-- HTTP SSE live stream
     |
pulse-agent       one-shot report CLI
pulse-server      server configuration/account CLI
```

The universal data object is a `Report`. Reports can contain normal system
metrics, zero or more operational events, or both.

Events enter Pulse only through the agent-to-server report protocol. The HTTP
API is read-only for events: it presents reports and stored events but does not
accept event submissions.

## Base URL and transport

The API base is configured by the server's `[api]` section:

```toml
[api]
enabled = true
bind = "127.0.0.1:9100"
tls = false
```

The Android app should use the deployed public URL, for example:

```text
https://pulse.example.com/api/v1
```

Do not expose the default plaintext listener directly to the internet. Use
`[api] tls = true` with a certificate, or put a TLS-terminating reverse proxy
in front of the loopback HTTP listener.

The API uses JSON over HTTP. All protected requests use:

```http
Authorization: Bearer <token>
```

The SSE endpoint also supports `?token=<token>` because Android/browser-style
EventSource clients may not be able to add an Authorization header.

## Authentication

### Login

```http
POST /api/v1/login
Content-Type: application/json
```

Request:

```json
{
  "username": "alice",
  "password": "the-user-password"
}
```

Success: `200 OK`

```json
{
  "token": "opaque-token",
  "expires_at_ms": 1789137692895
}
```

The token is opaque. Store it securely in Android Keystore-backed storage or
another encrypted credential store. Do not log it.

The server stores only `sha256(token)`. Sessions normally last seven days, but
the server controls the exact duration.

Possible failures:

| status | meaning |
|---|---|
| `401` | wrong username or password |
| `429` | login rate limit exceeded |
| `500` | server-side failure |

### Logout

```http
POST /api/v1/logout
Authorization: Bearer <token>
```

Success: `204 No Content`.

After logout, discard the token. Requests made with it return `401`.

### Authentication client behavior

The Android client should:

1. Log in and store the token and expiry timestamp.
2. Add the bearer token to every protected request.
3. Treat `401` as an expired/invalid session and require login again.
4. Treat `429` as a temporary condition and back off.
5. Never retry login aggressively.
6. Never put the bearer token in normal logs or crash reports.

## API endpoints

### Health check

```http
GET /api/v1/healthz
```

No authentication required.

Success:

```text
200 OK
ok
```

### Host list

```http
GET /api/v1/hosts
Authorization: Bearer <token>
```

Response:

```json
[
  {
    "machine_id": "c799f495523e5d75647cb253661b8d01",
    "hostname": "server",
    "os": "Ubuntu",
    "os_version": "22.04",
    "kernel_version": "5.15.0-142-generic",
    "first_seen_ms": 1788468451286,
    "last_seen_ms": 1788532890962,
    "last_peer": "127.0.0.1",
    "report_count": 12024,
    "online": true,
    "latest": {
      "ts_ms": 1788532890956,
      "cpu_pct": 28.77698,
      "mem_used_bytes": 3233247232,
      "mem_total_bytes": 6208946176,
      "load1": 0.29
    }
  }
]
```

`machine_id` is the stable host identifier. Use it as the host key in Android
state and navigation. `hostname` is display data and may change.

`online` is calculated by the server from `last_seen_ms` and its configured
`online_secs` threshold.

### Host detail

```http
GET /api/v1/hosts/{machine_id}
Authorization: Bearer <token>
```

Success: `200 OK`

```json
{
  "summary": {
    "machine_id": "host-id",
    "hostname": "server",
    "os": "Ubuntu",
    "os_version": "22.04",
    "kernel_version": "5.15.0-142-generic",
    "first_seen_ms": 1788468451286,
    "last_seen_ms": 1788532890962,
    "last_peer": "127.0.0.1",
    "report_count": 12024,
    "online": true,
    "latest": {
      "ts_ms": 1788532890956,
      "cpu_pct": 28.77698,
      "mem_used_bytes": 3233247232,
      "mem_total_bytes": 6208946176,
      "load1": 0.29
    }
  },
  "report": {
    "schema_version": 1,
    "host": {
      "machine_id": "host-id",
      "hostname": "server",
      "os": "Ubuntu",
      "os_version": "22.04",
      "kernel_version": "5.15.0-142-generic"
    },
    "timestamp_unix_ms": 1788532890956,
    "metrics": {},
    "events": []
  }
}
```

`report` is the complete report, including detailed metrics and events. The
`events` property is always present, including when it is empty.

### Numeric history

```http
GET /api/v1/hosts/{machine_id}/history
    ?from=<unix-ms>
    &to=<unix-ms>
    &bucket=<milliseconds>
Authorization: Bearer <token>
```

All query parameters are optional:

- Default range: the last hour.
- `from` is inclusive.
- `to` is exclusive.
- `bucket` is automatically selected when omitted.
- `bucket` must be greater than zero when supplied.

Response:

```json
{
  "machine_id": "host-id",
  "from_ms": 1788529290000,
  "to_ms": 1788532890000,
  "bucket_ms": 10000,
  "buckets": [
    {
      "ts_ms": 1788529290000,
      "cpu_avg": 12.435896873474121,
      "cpu_max": 13.333332061767578,
      "mem_used_avg": 3669291008.0,
      "mem_used_max": 3669295104,
      "load1_avg": 0.155,
      "samples": 2
    }
  ]
}
```

This endpoint is for charts. It does not return events.

### Complete report history

```http
GET /api/v1/hosts/{machine_id}/reports
    ?from=<unix-ms>
    &to=<unix-ms>
    &limit=<number>
Authorization: Bearer <token>
```

Defaults:

- last hour if `from` and `to` are omitted
- limit `1000`
- maximum limit `5000`

Response is an array of complete `Report` objects in chronological order.
Reports include `metrics` and `events`.

### Event history

```http
GET /api/v1/hosts/{machine_id}/events
    ?from=<unix-ms>
    &to=<unix-ms>
    &limit=<number>
Authorization: Bearer <token>
```

Defaults:

- last hour if `from` and `to` are omitted
- limit `1000`
- maximum limit `5000`

Response:

```json
[
  {
    "id": 42,
    "machine_id": "host-id",
    "timestamp_unix_ms": 1788532890956,
    "received_unix_ms": 1788532890962,
    "event": {
      "SshLogin": {
        "username": "alice",
        "source": "203.0.113.8",
        "success": true,
        "auth_method": "publickey"
      }
    }
  },
  {
    "id": 43,
    "machine_id": "host-id",
    "timestamp_unix_ms": 1788532900000,
    "received_unix_ms": 1788532900010,
    "event": {
      "Warning": {
        "code": "disk-nearly-full",
        "message": "Less than 10% space remains",
        "details": "/var"
      }
    }
  }
]
```

The returned event records are ordered chronologically. `id` is a server-side
database identifier. `timestamp_unix_ms` is the report/event timestamp from the
agent; `received_unix_ms` is when the server accepted the report.

There is intentionally no `POST /events` endpoint. The API returns `405` for
event submission attempts. Events must be sent inside reports through the
agent-to-server protocol, normally using:

```sh
pulse-agent report ssh-login ...
pulse-agent report warning ...
pulse-agent report custom ...
```

### Live stream

```http
GET /api/v1/live
Authorization: Bearer <token>
```

Alternative authentication:

```http
GET /api/v1/live?token=<token>
```

Response content type:

```text
text/event-stream
```

The server first sends the latest report for every currently known host, then
sends one SSE event for every newly received report.

Each `data:` payload is a complete JSON `Report`:

```text
data: {"schema_version":1,"host":{...},"timestamp_unix_ms":...,"metrics":{...},"events":[...]}
```

The Android client should parse SSE records by collecting lines until a blank
line. A record's `data:` lines form the JSON payload. Ignore comment/keep-alive
lines such as:

```text
: ping
```

When the connection is interrupted:

1. Reconnect with exponential backoff.
2. Re-authenticate if the server returns `401`.
3. Refresh `/hosts` and relevant history after reconnect.
4. Do not assume no events were missed.

The stream is a current-state/live stream, not a guaranteed event-delivery
queue. Use `/events` or `/reports` to recover historical data.

## Report JSON model

The JSON representation uses the Rust/Serde enum representation. Event variants
are externally tagged:

```json
{
  "SshLogin": {
    "username": "alice",
    "source": "203.0.113.8",
    "success": true,
    "auth_method": "publickey"
  }
}
```

```json
{
  "Warning": {
    "code": "certificate-expiring",
    "message": "Certificate expires soon",
    "details": "expires in 14 days"
  }
}
```

```json
{
  "Custom": {
    "name": "deployment",
    "message": "version changed",
    "fields": {
      "version": "1.2.3",
      "environment": "production"
    }
  }
}
```

The complete report shape is:

```json
{
  "schema_version": 1,
  "host": {
    "machine_id": "host-id",
    "hostname": "server",
    "os": "Ubuntu",
    "os_version": "22.04",
    "kernel_version": "5.15"
  },
  "timestamp_unix_ms": 1788532890956,
  "metrics": {
    "cpu": {
      "global_usage_percent": 28.7,
      "per_core_usage_percent": [20.0, 31.0],
      "core_count": 2
    },
    "memory": {
      "total_bytes": 6208946176,
      "used_bytes": 3233247232,
      "free_bytes": 432365568,
      "swap_total_bytes": 2147479552,
      "swap_used_bytes": 1155350528
    },
    "disks": [
      {
        "name": "/dev/sda3",
        "mount_point": "/",
        "file_system": "ext4",
        "total_bytes": 419491782656,
        "available_bytes": 62209032192,
        "removable": false
      }
    ],
    "linux": {
      "load_avg_one": 0.29,
      "load_avg_five": 0.81,
      "load_avg_fifteen": 0.81,
      "uptime_secs": 37777717
    }
  },
  "events": []
}
```

Metric sections may be absent or empty depending on the collector and report
source. Do not assume every metric section exists. Use null/missing-safe models.

## Event semantics

### SSH login

```json
{
  "SshLogin": {
    "username": "alice",
    "source": "203.0.113.8",
    "success": true,
    "auth_method": "publickey"
  }
}
```

`success` distinguishes accepted and rejected attempts. `source` is supplied by
the event producer and should be displayed as an address or source label.

### Warning

```json
{
  "Warning": {
    "code": "service-down",
    "message": "nginx is not running",
    "details": "systemctl status nginx"
  }
}
```

Use `code` for filtering/grouping and `message` for display. `details` is
optional.

### Custom event

```json
{
  "Custom": {
    "name": "backup",
    "message": "backup completed",
    "fields": {
      "duration_seconds": "42",
      "result": "success"
    }
  }
}
```

Custom field values are strings. Convert them explicitly in the Android layer
when a known integration gives them numeric or boolean meaning.

## Error format

API errors use JSON:

```json
{
  "error": "unknown host"
}
```

Common statuses:

| status | meaning |
|---|---|
| `400` | invalid query range or request |
| `401` | missing, invalid, or expired session |
| `404` | unknown host |
| `405` | unsupported method, including event POST |
| `429` | login rate limit |
| `500` | internal server/storage failure |

## Recommended Android data layer

Use separate models for:

```text
HostSummary
HostDetail
Report
Metrics
ReportEvent
StoredEvent
History
```

Recommended repository responsibilities:

```text
AuthRepository
    login/logout/token storage

HostRepository
    list hosts
    host detail

MetricsRepository
    numeric history
    complete reports

EventRepository
    event history

LiveRepository
    authenticated SSE connection
    reconnect/backoff
```

Suggested UI data flow:

```text
login
  |
load /hosts
  |
select host
  ├── /hosts/{id}
  ├── /history
  ├── /reports
  └── /events
  |
subscribe /live for current updates
```

Keep the SSE stream as a live-update source and use REST endpoints as the
authoritative source for screen refresh and missed data recovery.

## Time handling

All timestamps are Unix epoch milliseconds in UTC:

```text
timestamp_unix_ms
first_seen_ms
last_seen_ms
received_unix_ms
```

In Kotlin:

```kotlin
val instant = Instant.ofEpochMilli(timestampUnixMs)
```

Render in the user's local timezone, but store and compare timestamps as UTC
epoch milliseconds.

## Pagination and limits

There is no cursor pagination. Time ranges and integer limits are used instead.

For large event/report histories:

1. Request a bounded time range.
2. Use `limit <= 5000`.
3. Move the `from`/`to` window forward for additional data.
4. Treat `to` as exclusive.

The live stream can lag or disconnect. It should not be used as the only source
for durable event history.

## Security requirements for the Android app

- Use HTTPS for all remote API traffic.
- Do not disable certificate validation in production.
- Store tokens securely.
- Do not log authorization headers or passwords.
- Clear tokens on logout and account reset.
- Handle `401` by returning to login.
- Handle `429` with backoff.
- Do not expose event submission UI through the API because the server does not
  support API event writes.
- Treat event messages as untrusted display data and escape them in the UI.

## Current server implementation map

| area | source |
|---|---|
| report/event protocol | `crates/protocol/src/report.rs` |
| MessagePack framing | `crates/protocol/src/frame.rs` |
| agent event CLI | `crates/agent-cli/src/main.rs` |
| server ingest | `crates/server/src/connection.rs` |
| live memory/SSE source | `crates/server/src/live.rs` |
| HTTP routes | `crates/server/src/api/routes.rs` |
| API authentication | `crates/server/src/api/auth.rs` |
| API response models | `crates/server/src/api/dto.rs` |
| SQLite interface | `crates/server/src/store/mod.rs` |
| SQLite implementation | `crates/server/src/store/sqlite.rs` |
| server configuration | `crates/server/src/config.rs` |
| TLS and logging | `crates/pulse-config/src/tls.rs`, `log.rs` |

## Important contract summary

```text
Events are read through the API, never written through the API.

Write path:
  agent/protocol Report -> server validation -> SQLite + Live

Read paths:
  /hosts/{id}       latest complete Report
  /reports          complete historical Reports
  /events           flattened stored event records
  /live             current snapshot + new complete Reports

Charts:
  /history          numeric downsampled metrics only
```
