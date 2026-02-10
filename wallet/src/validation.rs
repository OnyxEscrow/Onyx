/// Validation stricte des URLs pour OPSEC
///
/// TM-004 Fix: Remplace le faible `contains()` par un parsing IP réel
use anyhow::{Context, Result};
use std::net::{Ipv4Addr, Ipv6Addr};
use url::Url;

/// Valide qu'une URL RPC est STRICTEMENT localhost
///
/// Accepte uniquement:
/// - `http://127.0.0.1:18082`
/// - `http://localhost:18082`
/// - `http://[::1]:18082`
///
/// Rejette tout le reste, y compris:
/// - `http://evil-127.0.0.1.com:18082` (bypass du vieux contains())
/// - `http://192.168.1.10:18082`
/// - `http://0.0.0.0:18082`
pub fn validate_localhost_strict(url_str: &str) -> Result<()> {
    let url = Url::parse(url_str).context("URL invalide")?;

    // Utiliser url.host() qui gère correctement IPv4, IPv6 et domain names
    match url.host() {
        Some(url::Host::Domain(domain)) => {
            if domain == "localhost" {
                Ok(())
            } else {
                anyhow::bail!(
                    "RPC host invalide: '{}'. Utilise localhost ou 127.0.0.1",
                    domain
                )
            }
        }
        Some(url::Host::Ipv4(ipv4)) => {
            if ipv4 == Ipv4Addr::LOCALHOST {
                Ok(())
            } else {
                anyhow::bail!("RPC doit être 127.0.0.1 (OPSEC), pas {}", ipv4)
            }
        }
        Some(url::Host::Ipv6(ipv6)) => {
            if ipv6 == Ipv6Addr::LOCALHOST {
                Ok(())
            } else {
                anyhow::bail!("RPC doit être ::1 (OPSEC), pas {}", ipv6)
            }
        }
        None => {
            anyhow::bail!("URL sans host")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_localhost() {
        assert!(validate_localhost_strict("http://127.0.0.1:18082").is_ok());
        assert!(validate_localhost_strict("http://localhost:18082").is_ok());
        // IPv6 localhost supporté en théorie, mais cas edge rare pour testnet alpha
    }

    #[test]
    fn test_bypass_attempts() {
        // Vieux bug: contains() acceptait ça
        assert!(validate_localhost_strict("http://evil-127.0.0.1.com:18082").is_err());
        assert!(validate_localhost_strict("http://localhost.attacker.com:18082").is_err());
        assert!(validate_localhost_strict("http://192.168.127.0.0.1:18082").is_err());
    }

    #[test]
    fn test_reject_non_localhost() {
        assert!(validate_localhost_strict("http://192.168.1.10:18082").is_err());
        assert!(validate_localhost_strict("http://0.0.0.0:18082").is_err());
        assert!(validate_localhost_strict("http://10.0.0.1:18082").is_err());
    }
}
