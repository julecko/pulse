use protocol::{AgentSummary, ApproveResponse};

pub async fn list(client: &reqwest::Client, base: &str) -> Result<(), String> {
    let agents: Vec<AgentSummary> = client
        .get(format!("{base}/agents"))
        .send()
        .await
        .map_err(|e| format!("request failed: {e}"))?
        .error_for_status()
        .map_err(|e| format!("server error: {e}"))?
        .json()
        .await
        .map_err(|e| format!("invalid response: {e}"))?;

    if agents.is_empty() {
        println!("no agents");
        return Ok(());
    }

    println!(
        "{:<4} {:<9} {:<20} {:<36} {:<20}",
        "ID", "STATUS", "HOSTNAME", "FINGERPRINT", "CREATED_AT"
    );
    for agent in agents {
        println!(
            "{:<4} {:<9} {:<20} {:<36} {:<20}",
            agent.id, agent.status, agent.hostname, agent.fingerprint, agent.created_at
        );
    }
    Ok(())
}

pub async fn approve(client: &reqwest::Client, base: &str, id: i64) -> Result<(), String> {
    let resp: ApproveResponse = client
        .post(format!("{base}/agents/{id}/approve"))
        .send()
        .await
        .map_err(|e| format!("request failed: {e}"))?
        .error_for_status()
        .map_err(|e| format!("server error: {e}"))?
        .json()
        .await
        .map_err(|e| format!("invalid response: {e}"))?;

    println!("approved agent {id}, token: {}", resp.token);
    Ok(())
}

pub async fn revoke(client: &reqwest::Client, base: &str, id: i64) -> Result<(), String> {
    client
        .post(format!("{base}/agents/{id}/revoke"))
        .send()
        .await
        .map_err(|e| format!("request failed: {e}"))?
        .error_for_status()
        .map_err(|e| format!("server error: {e}"))?;

    println!("revoked agent {id}");
    Ok(())
}

pub async fn remove(client: &reqwest::Client, base: &str, id: i64) -> Result<(), String> {
    client
        .delete(format!("{base}/agents/{id}"))
        .send()
        .await
        .map_err(|e| format!("request failed: {e}"))?
        .error_for_status()
        .map_err(|e| format!("server error: {e}"))?;

    println!("removed agent {id}");
    Ok(())
}
