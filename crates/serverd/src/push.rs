//! Push notifications for alerts, via Firebase Cloud Messaging (FCM HTTP
//! v1), to every device in `push_devices` (all users).
//!
//! Configured by `[push] fcm_service_account`: the service account JSON key
//! from the Firebase console (Project settings > Service accounts). Unset:
//! alerts are still recorded, just not pushed.
//!
//! FCM wants an OAuth2 access token: we sign a JWT with the service
//! account's RSA key (RS256), exchange it at the account's `token_uri`, and
//! reuse the result until shortly before it expires.
//!
//! Pushes are sent in the background and never hold up metrics ingestion.
//! What's sent (rule name, hostname, metric value) passes through Google.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use ring::rand::SystemRandom;
use ring::signature::{RSA_PKCS1_SHA256, RsaKeyPair};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use tokio::sync::Mutex;

const FCM_SCOPE: &str = "https://www.googleapis.com/auth/firebase.messaging";
const DEFAULT_FCM_API_URL: &str = "https://fcm.googleapis.com";
/// Longest a request to Google may take.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
/// Access tokens are refreshed this long before they expire.
const TOKEN_REFRESH_MARGIN: Duration = Duration::from_secs(60);

/// The server config's `[push]` section.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PushConfig {
    /// Firebase service account JSON key. Unset: pushes are disabled.
    pub fcm_service_account: Option<PathBuf>,
    /// FCM API base URL; only for testing against a local stand-in.
    pub fcm_api_url: Option<String>,
}

/// What an alert push says.
#[derive(Debug, Clone)]
pub struct AlertPush {
    pub alert_id: i64,
    pub agent_id: i64,
    pub severity: String,
    pub title: String,
    pub message: String,
}

/// Sends alert pushes; a no-op when `[push]` isn't configured.
pub struct Push {
    fcm: Option<Arc<Fcm>>,
}

impl Push {
    pub fn from_config(cfg: &PushConfig) -> Result<Self, String> {
        let Some(path) = &cfg.fcm_service_account else {
            tracing::info!("push notifications disabled ([push] fcm_service_account unset)");
            return Ok(Self { fcm: None });
        };
        let json = std::fs::read_to_string(path)
            .map_err(|e| format!("reading {}: {e}", path.display()))?;
        let account: ServiceAccount = serde_json::from_str(&json)
            .map_err(|e| format!("parsing service account {}: {e}", path.display()))?;
        let key = rsa_key_from_pem(&account.private_key)
            .map_err(|e| format!("service account {} private_key: {e}", path.display()))?;
        let client = reqwest::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .build()
            .map_err(|e| format!("building HTTP client: {e}"))?;

        tracing::info!(project = %account.project_id, "push notifications enabled (FCM)");
        Ok(Self {
            fcm: Some(Arc::new(Fcm {
                client,
                api_url: cfg
                    .fcm_api_url
                    .clone()
                    .unwrap_or_else(|| DEFAULT_FCM_API_URL.to_string()),
                account,
                key,
                access_token: Mutex::new(None),
            })),
        })
    }

    /// Pushes `alert` to every registered device, in the background.
    pub fn notify_all(&self, pool: &SqlitePool, alert: AlertPush) {
        let Some(fcm) = &self.fcm else {
            tracing::debug!(
                alert_id = alert.alert_id,
                "push not configured; not sending"
            );
            return;
        };
        let fcm = Arc::clone(fcm);
        let pool = pool.clone();
        tokio::spawn(async move { fcm.send_to_all(&pool, &alert).await });
    }
}

#[derive(Deserialize)]
struct ServiceAccount {
    project_id: String,
    client_email: String,
    private_key: String,
    token_uri: String,
}

struct Fcm {
    client: reqwest::Client,
    api_url: String,
    account: ServiceAccount,
    key: RsaKeyPair,
    /// Current access token and when to stop using it.
    access_token: Mutex<Option<(String, Instant)>>,
}

enum SendError {
    /// The app was uninstalled or the token expired: forget the device.
    Unregistered,
    Other(String),
}

impl Fcm {
    async fn send_to_all(&self, pool: &SqlitePool, alert: &AlertPush) {
        let devices: Vec<(i64, String)> = match sqlx::query_as("SELECT id, token FROM push_devices")
            .fetch_all(pool)
            .await
        {
            Ok(devices) => devices,
            Err(err) => {
                tracing::warn!(%err, alert_id = alert.alert_id, "push: failed to load devices");
                return;
            }
        };
        if devices.is_empty() {
            tracing::debug!(alert_id = alert.alert_id, "push: no registered devices");
            return;
        }

        let access_token = match self.access_token().await {
            Ok(token) => token,
            Err(err) => {
                tracing::warn!(%err, alert_id = alert.alert_id, "push: failed to get FCM access token");
                return;
            }
        };

        let (mut sent, mut failed) = (0, 0);
        for (device_id, token) in devices {
            match self.send(&access_token, &token, alert).await {
                Ok(()) => sent += 1,
                Err(SendError::Unregistered) => {
                    tracing::info!(
                        device_id,
                        "push: device no longer registered with FCM; removing it"
                    );
                    if let Err(err) = sqlx::query("DELETE FROM push_devices WHERE id = ?")
                        .bind(device_id)
                        .execute(pool)
                        .await
                    {
                        tracing::warn!(%err, device_id, "push: failed to remove device");
                    }
                }
                Err(SendError::Other(err)) => {
                    failed += 1;
                    tracing::warn!(%err, device_id, alert_id = alert.alert_id, "push: send failed");
                }
            }
        }
        tracing::info!(alert_id = alert.alert_id, sent, failed, "push: alert sent");
    }

    async fn send(
        &self,
        access_token: &str,
        device_token: &str,
        alert: &AlertPush,
    ) -> Result<(), SendError> {
        let body = serde_json::json!({
            "message": {
                "token": device_token,
                "notification": { "title": alert.title, "body": alert.message },
                // Data values must be strings.
                "data": {
                    "alert_id": alert.alert_id.to_string(),
                    "agent_id": alert.agent_id.to_string(),
                    "severity": alert.severity,
                },
                "android": { "priority": "high" },
            }
        });
        let url = format!(
            "{}/v1/projects/{}/messages:send",
            self.api_url, self.account.project_id
        );
        let resp = self
            .client
            .post(url)
            .bearer_auth(access_token)
            .json(&body)
            .send()
            .await
            .map_err(|e| SendError::Other(e.to_string()))?;

        let status = resp.status();
        if status.is_success() {
            return Ok(());
        }
        let text = resp.text().await.unwrap_or_default();
        // 404 NOT_FOUND / UNREGISTERED is how FCM says the token is dead.
        if status == reqwest::StatusCode::NOT_FOUND || text.contains("UNREGISTERED") {
            return Err(SendError::Unregistered);
        }
        let text: String = text.chars().take(500).collect();
        Err(SendError::Other(format!("{status}: {text}")))
    }

    /// A cached access token, or a fresh one if it's (nearly) expired.
    async fn access_token(&self) -> Result<String, String> {
        let mut cached = self.access_token.lock().await;
        if let Some((token, valid_until)) = cached.as_ref()
            && Instant::now() < *valid_until
        {
            return Ok(token.clone());
        }

        #[derive(Deserialize)]
        struct TokenResponse {
            access_token: String,
            expires_in: u64,
        }

        let assertion = self.signed_jwt()?;
        let resp = self
            .client
            .post(&self.account.token_uri)
            .form(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
                ("assertion", assertion.as_str()),
            ])
            .send()
            .await
            .map_err(|e| format!("token request: {e}"))?;
        let status = resp.status();
        if !status.is_success() {
            let text: String = resp
                .text()
                .await
                .unwrap_or_default()
                .chars()
                .take(500)
                .collect();
            return Err(format!("token request: {status}: {text}"));
        }
        let token: TokenResponse = resp
            .json()
            .await
            .map_err(|e| format!("token response: {e}"))?;

        let lifetime = Duration::from_secs(token.expires_in).saturating_sub(TOKEN_REFRESH_MARGIN);
        *cached = Some((token.access_token.clone(), Instant::now() + lifetime));
        Ok(token.access_token)
    }

    /// The RS256 JWT exchanged for an access token.
    fn signed_jwt(&self) -> Result<String, String> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| e.to_string())?
            .as_secs();
        let header = serde_json::json!({ "alg": "RS256", "typ": "JWT" });
        let claims = serde_json::json!({
            "iss": self.account.client_email,
            "scope": FCM_SCOPE,
            "aud": self.account.token_uri,
            "iat": now,
            "exp": now + 3600,
        });
        let signing_input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header.to_string()),
            URL_SAFE_NO_PAD.encode(claims.to_string())
        );
        let mut signature = vec![0u8; self.key.public().modulus_len()];
        self.key
            .sign(
                &RSA_PKCS1_SHA256,
                &SystemRandom::new(),
                signing_input.as_bytes(),
                &mut signature,
            )
            .map_err(|_| "signing JWT failed".to_string())?;
        Ok(format!(
            "{signing_input}.{}",
            URL_SAFE_NO_PAD.encode(signature)
        ))
    }
}

/// Parses a PEM `PRIVATE KEY` (PKCS#8, as in Google service account keys).
fn rsa_key_from_pem(pem: &str) -> Result<RsaKeyPair, String> {
    let b64: String = pem
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with("-----"))
        .collect();
    let der = STANDARD
        .decode(b64)
        .map_err(|e| format!("invalid PEM: {e}"))?;
    RsaKeyPair::from_pkcs8(&der).map_err(|e| format!("not a PKCS#8 RSA key: {e}"))
}
