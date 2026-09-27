//! IP geolocation from a MaxMind GeoLite2 City database (`.mmdb`), for geo
//! alerts (see [`crate::geo_alerts`]).
//!
//! The file isn't shipped (MaxMind's license needs a free account): download
//! `GeoLite2-City.mmdb` yourself, ideally with MaxMind's `geoipupdate`, which
//! keeps it at `/var/lib/GeoIP/GeoLite2-City.mmdb`. Absent `[geoip]
//! database` in the server config:
//! - debug build: `./GeoLite2-City.mmdb` (the repo root; it's gitignored)
//! - release build: `/var/lib/GeoIP/GeoLite2-City.mmdb`
//!
//! It's read once at startup, so restart the server after updating it. A
//! missing or unreadable file only disables geo alerts.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};

use maxminddb::{Reader, geoip2};
use serde::{Deserialize, Serialize};

/// Release default database file; where `geoipupdate` puts it.
pub const DEFAULT_DATABASE: &str = "/var/lib/GeoIP/GeoLite2-City.mmdb";

/// The server config's `[geoip]` section.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct GeoIpConfig {
    /// GeoLite2 City database. Unset: see the module docs.
    pub database: Option<PathBuf>,
}

impl GeoIpConfig {
    pub fn resolved_database(&self) -> PathBuf {
        self.database.clone().unwrap_or_else(|| {
            if cfg!(debug_assertions) {
                PathBuf::from("GeoLite2-City.mmdb")
            } else {
                PathBuf::from(DEFAULT_DATABASE)
            }
        })
    }
}

/// Where an IP is, as far as the database knows.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Location {
    /// ISO 3166-1 alpha-2, e.g. `SK`; `None` if the IP isn't in the database.
    pub country_code: Option<String>,
    pub country_name: Option<String>,
    pub city: Option<String>,
}

/// The loaded database, if any.
pub struct GeoIp {
    reader: Option<(PathBuf, Reader<Vec<u8>>)>,
}

impl GeoIp {
    pub fn load(cfg: &GeoIpConfig) -> Self {
        let path = cfg.resolved_database();
        match Reader::open_readfile(&path) {
            Ok(reader) => {
                tracing::info!(
                    path = %path.display(),
                    database_type = %reader.metadata().database_type,
                    "GeoIP database loaded; geo alerts available"
                );
                Self {
                    reader: Some((path, reader)),
                }
            }
            Err(err) => {
                tracing::info!(path = %path.display(), %err, "no GeoIP database; geo alerts disabled");
                Self { reader: None }
            }
        }
    }

    /// The loaded file, its type (e.g. `GeoLite2-City`) and build time
    /// (Unix seconds).
    pub fn database(&self) -> Option<(&Path, &str, u64)> {
        self.reader.as_ref().map(|(path, reader)| {
            let meta = reader.metadata();
            (
                path.as_path(),
                meta.database_type.as_str(),
                meta.build_epoch,
            )
        })
    }

    /// Where `ip` is; `None` if no database is loaded. An IP the database
    /// doesn't know gives an empty [`Location`].
    pub fn lookup(&self, ip: IpAddr) -> Option<Location> {
        let (_, reader) = self.reader.as_ref()?;
        let city = match reader.lookup(ip).and_then(|r| r.decode::<geoip2::City>()) {
            Ok(Some(city)) => city,
            Ok(None) => return Some(Location::default()),
            Err(err) => {
                tracing::warn!(%ip, %err, "GeoIP lookup failed");
                return Some(Location::default());
            }
        };
        Some(Location {
            country_code: city.country.iso_code.map(str::to_string),
            country_name: city.country.names.english.map(str::to_string),
            city: city.city.names.english.map(str::to_string),
        })
    }
}

/// Whether `ip` is on the public internet, i.e. worth looking up: not
/// loopback, private, carrier-grade NAT, link-local, documentation, ...
/// (logins over a LAN or VPN have no country).
pub fn is_public(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(v4) => is_public_v4(v4),
        IpAddr::V6(v6) => is_public_v6(v6),
    }
}

fn is_public_v4(ip: Ipv4Addr) -> bool {
    let [a, b, ..] = ip.octets();
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_documentation()
        || ip.is_multicast()
        // 100.64.0.0/10, carrier-grade NAT (also Tailscale)
        || (a == 100 && (64..128).contains(&b))
        // 0.0.0.0/8 and 240.0.0.0/4, reserved
        || a == 0
        || a >= 240)
}

fn is_public_v6(ip: Ipv6Addr) -> bool {
    let first = ip.segments()[0];
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        // fc00::/7, unique local
        || (first & 0xfe00) == 0xfc00
        // fe80::/10, link-local
        || (first & 0xffc0) == 0xfe80
        // 2001:db8::/32, documentation
        || (first == 0x2001 && ip.segments()[1] == 0x0db8))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn public(s: &str) -> bool {
        is_public(s.parse().unwrap())
    }

    #[test]
    fn tells_public_ips_from_local_ones() {
        assert!(public("81.2.69.142"));
        assert!(public("2a02:ab88::1"));
        assert!(public("::ffff:81.2.69.142"));
        for local in [
            "127.0.0.1",
            "10.1.2.3",
            "192.168.1.10",
            "172.16.0.1",
            "100.100.1.1",
            "169.254.1.1",
            "192.0.2.7",
            "0.0.0.0",
            "::1",
            "fd00::1",
            "fe80::1",
            "2001:db8::1",
            "::ffff:10.0.0.1",
        ] {
            assert!(!public(local), "{local} should not be public");
        }
    }
}
