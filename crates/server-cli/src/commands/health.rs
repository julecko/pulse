pub async fn check(client: &reqwest::Client, base: &str) -> Result<(), String> {
    let resp = client
        .get(format!("{base}/healthz"))
        .send()
        .await
        .map_err(|e| format!("request failed: {e}"))?;

    let status = resp.status();
    if status.is_success() {
        println!("ok ({status})");
        Ok(())
    } else {
        Err(format!("server responded with {status}"))
    }
}
