use std::collections::HashMap;
use std::net::IpAddr;

#[derive(Default)]
pub struct Registry {
    hosts: HashMap<String, Host>,
}

struct Host {
    hostname: String,
    reports: u64,
    last_peer: IpAddr,
}

pub struct Seen {
    pub verdict: Verdict,
    pub reports: u64,
    pub peer_changed_from: Option<IpAddr>,
}

pub enum Verdict {
    New,
    Known,
    Renamed { previous: String },
}

impl Registry {
    pub fn record(&mut self, machine_id: &str, hostname: &str, peer: IpAddr) -> Seen {
        match self.hosts.get_mut(machine_id) {
            None => {
                self.hosts.insert(
                    machine_id.to_owned(),
                    Host {
                        hostname: hostname.to_owned(),
                        reports: 1,
                        last_peer: peer,
                    },
                );
                Seen {
                    verdict: Verdict::New,
                    reports: 1,
                    peer_changed_from: None,
                }
            }
            Some(host) => {
                host.reports += 1;
                let peer_changed_from = (host.last_peer != peer).then_some(host.last_peer);
                host.last_peer = peer;
                let verdict = if host.hostname != hostname {
                    let previous = std::mem::replace(&mut host.hostname, hostname.to_owned());
                    Verdict::Renamed { previous }
                } else {
                    Verdict::Known
                };
                Seen {
                    verdict,
                    reports: host.reports,
                    peer_changed_from,
                }
            }
        }
    }

    pub fn others_named(&self, hostname: &str, machine_id: &str) -> Vec<String> {
        self.hosts
            .iter()
            .filter(|(id, h)| h.hostname == hostname && id.as_str() != machine_id)
            .map(|(id, _)| id.clone())
            .collect()
    }
}
