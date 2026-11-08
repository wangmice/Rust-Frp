//! 客户端服务端地址解析：TXT → IP4P AAAA → A → 普通 AAAA。
use anyhow::{bail, Result};
use base64::Engine;
use hickory_resolver::{
    config::{NameServerConfig, ResolveHosts, ResolverConfig, ResolverOpts},
    net::runtime::TokioRuntimeProvider,
    proto::rr::RData,
    TokioResolver,
};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::time::timeout;

// Bound application-level TXT work independently of the DNS packet limit.
const MAX_TXT_RECORDS: usize = 16;
const MAX_TXT_BYTES: usize = 1024;
// Discovery must leave time for connecting within the default ten-second login.
const SPECIAL_QUERY_BUDGET: Duration = Duration::from_secs(1);
const ORDINARY_QUERY_BUDGET: Duration = Duration::from_secs(3);

/// Resolve literals without DNS, otherwise prefer TXT endpoints, IP4P, A, then AAAA.
/// An empty DNS server probes special records using system DNS configuration, then
/// uses native getaddrinfo (including hosts, NSS and platform split DNS) for IPs.
/// TXT processing examines at most 16 records, each no larger than 1024 bytes.
pub async fn resolve_server_addr(dns_server: &str, host: &str, port: u16) -> Result<SocketAddr> {
    let literal = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    if let Ok(ip) = literal.parse::<std::net::IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }
    if dns_server.trim().is_empty() {
        // Optional discovery must not disable the native resolver if reading
        // the platform DNS configuration fails.
        let resolver = TokioResolver::builder_tokio()
            .ok()
            .and_then(|builder| builder.build().ok());
        return resolve_system(resolver.as_ref(), host, port).await;
    }
    let resolver = {
        let server = dns_server.trim().parse::<SocketAddr>().or_else(|_| {
            dns_server
                .trim()
                .trim_matches(['[', ']'])
                .parse()
                .map(|ip| SocketAddr::new(ip, 53))
        })?;
        let config = custom_dns_config(server);
        let mut opts = ResolverOpts::default();
        opts.ip_strategy = hickory_resolver::config::LookupIpStrategy::Ipv4thenIpv6;
        opts.use_hosts_file = ResolveHosts::Never;
        TokioResolver::builder_with_config(config, TokioRuntimeProvider::default())
            .with_options(opts)
            .build()?
    };
    resolve_with(&resolver, host, port).await
}

fn custom_dns_config(server: SocketAddr) -> ResolverConfig {
    let mut nameserver = NameServerConfig::udp_and_tcp(server.ip());
    for connection in &mut nameserver.connections {
        connection.port = server.port();
    }
    ResolverConfig::from_name_servers(vec![nameserver])
}

async fn resolve_system(
    resolver: Option<&TokioResolver>,
    host: &str,
    port: u16,
) -> Result<SocketAddr> {
    if let Some(resolver) = resolver {
        if let Some(addr) = resolve_special(resolver, host).await {
            return Ok(addr);
        }
    }
    // Keep NSS/mDNS and platform split DNS: resolv.conf is not getaddrinfo.
    let mut addresses =
        timeout(ORDINARY_QUERY_BUDGET, tokio::net::lookup_host((host, port))).await??;
    addresses
        .find(|addr| !matches!(addr.ip(), std::net::IpAddr::V6(ip) if is_ip4p(ip)))
        .ok_or_else(|| anyhow::anyhow!("系统解析没有可用的服务端地址"))
}

async fn resolve_with(resolver: &TokioResolver, host: &str, port: u16) -> Result<SocketAddr> {
    if let Some(addr) = resolve_special(resolver, host).await {
        return Ok(addr);
    }
    if let Ok(Ok(records)) = timeout(ORDINARY_QUERY_BUDGET, resolver.lookup_ip(host)).await {
        if let Some(ip) = records
            .iter()
            .find(|ip| !matches!(ip, std::net::IpAddr::V6(ip) if is_ip4p(*ip)))
        {
            return Ok(SocketAddr::new(ip, port));
        }
    }
    bail!("DNS 没有可用的服务端地址")
}

async fn resolve_special(resolver: &TokioResolver, host: &str) -> Option<SocketAddr> {
    if let Ok(Ok(records)) = timeout(SPECIAL_QUERY_BUDGET, resolver.txt_lookup(host)).await {
        for record in records
            .answers()
            .iter()
            .filter_map(|record| match &record.data {
                RData::TXT(txt) => Some(txt),
                _ => None,
            })
            .take(MAX_TXT_RECORDS)
        {
            if record.txt_data.iter().map(|part| part.len()).sum::<usize>() > MAX_TXT_BYTES {
                continue;
            }
            let data: Vec<_> = record
                .txt_data
                .iter()
                .flat_map(|part| part.iter().copied())
                .collect();
            if let Some(addr) = parse_txt(&data) {
                return Some(addr);
            }
        }
    }
    if let Ok(Ok(records)) = timeout(SPECIAL_QUERY_BUDGET, resolver.ipv6_lookup(host)).await {
        for ip in records
            .answers()
            .iter()
            .filter_map(|record| match &record.data {
                RData::AAAA(ip) => Some(ip),
                _ => None,
            })
        {
            let bytes = ip.octets();
            if is_ip4p(**ip) {
                let port = u16::from_be_bytes([bytes[10], bytes[11]]);
                if port != 0 {
                    return Some(SocketAddr::new(
                        std::net::Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15]).into(),
                        port,
                    ));
                }
            }
        }
    }
    None
}

fn is_ip4p(ip: std::net::Ipv6Addr) -> bool {
    ip.octets()[..10] == [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0]
}

fn parse_txt(data: &[u8]) -> Option<SocketAddr> {
    use base64::{
        alphabet,
        engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig},
    };
    if data.len() > MAX_TXT_BYTES {
        return None;
    }
    let text = std::str::from_utf8(data)
        .ok()?
        .trim_matches(|c: char| c.is_ascii_whitespace());
    let text = if text.starts_with(['\'', '"']) {
        let quote = text.as_bytes()[0] as char;
        text.strip_prefix(quote)?
            .strip_suffix(quote)?
            .trim_matches(|c: char| c.is_ascii_whitespace())
    } else {
        text
    };
    let text: String = text.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    let standard = text.bytes().any(|b| b == b'+' || b == b'/');
    let urlsafe = text.bytes().any(|b| b == b'-' || b == b'_');
    if standard && urlsafe {
        return None;
    }
    let engine = GeneralPurpose::new(
        if urlsafe {
            &alphabet::URL_SAFE
        } else {
            &alphabet::STANDARD
        },
        GeneralPurposeConfig::new().with_decode_padding_mode(if text.contains('=') {
            DecodePaddingMode::RequireCanonical
        } else {
            DecodePaddingMode::RequireNone
        }),
    );
    let decoded = engine.decode(&text).ok()?;
    let value = std::str::from_utf8(&decoded).ok()?;
    if value
        .bytes()
        .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
    {
        return None;
    }
    let (ip, port) = value.split_once(':')?;
    if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let ip = ip.parse::<std::net::Ipv4Addr>().ok()?;
    let port = port.parse::<u16>().ok()?;
    (port != 0).then(|| SocketAddr::new(ip.into(), port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn dropped_special_queries_reach_a_within_login_budget() {
        let fixture = fixture_with_drops(vec![(1, vec![192, 0, 2, 3])], vec![16, 28]).await;
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(4),
            resolve_server_addr(&fixture.dns, "endpoint.test.", 7000),
        )
        .await
        .expect("dropped TXT/AAAA must not exhaust the ten-second login timeout")
        .unwrap();
        assert_eq!(result, "192.0.2.3:7000".parse().unwrap());
        let queries = fixture.seen.lock().unwrap();
        for kind in [16, 28, 1] {
            assert!(
                queries.contains(&kind),
                "missing query type {kind}: {queries:?}"
            );
        }
    }

    #[test]
    fn txt_ascii_whitespace_inside_encoding_is_ignored() {
        assert_eq!(
            parse_txt(b" 'MTkyLjAu\tMi4x\r\nOjgwODA=' "),
            Some("192.0.2.1:8080".parse().unwrap())
        );
    }

    // Special DNS answers win; ordinary answers must come from real getaddrinfo.
    #[tokio::test]
    async fn system_special_priority_then_native_localhost_fallback() {
        for use_txt in [true, false] {
            let records = if use_txt {
                vec![txt(&["MTkyLjAuMi4xOjgwODA="])]
            } else {
                vec![(1, vec![192, 0, 2, 9])]
            };
            let fixture = fixture(records).await;
            let config = custom_dns_config(fixture.dns.parse().unwrap());
            let mut opts = ResolverOpts::default();
            opts.use_hosts_file = ResolveHosts::Never;
            let resolver =
                TokioResolver::builder_with_config(config, TokioRuntimeProvider::default())
                    .with_options(opts)
                    .build()
                    .unwrap();
            let host = if use_txt {
                "endpoint.test."
            } else {
                "localhost"
            };
            let result = resolve_system(Some(&resolver), host, 7000).await.unwrap();
            if use_txt {
                assert_eq!(result, "192.0.2.1:8080".parse().unwrap());
            } else {
                assert!(
                    result.ip().is_loopback(),
                    "must use native localhost: {result}"
                );
                assert_eq!(result.port(), 7000);
            }
            assert_eq!(
                *fixture.seen.lock().unwrap(),
                if use_txt { vec![16] } else { vec![] }
            );
        }
    }

    #[tokio::test]
    async fn missing_system_dns_config_still_resolves_native_localhost() {
        let addr = resolve_system(None, "localhost", 7000).await.unwrap();
        assert!(addr.ip().is_loopback());
        assert_eq!(addr.port(), 7000);
    }

    #[tokio::test]
    async fn custom_dns_does_not_fall_back_to_system_hosts() {
        // This is present in the real local hosts file on this test host, but
        // the explicitly selected DNS server returns no ordinary addresses.
        let fixture = fixture(vec![]).await;
        assert!(resolve_server_addr(&fixture.dns, "ip6-localhost", 7000)
            .await
            .is_err());
        assert!(fixture.seen.lock().unwrap().contains(&1));
    }

    #[tokio::test]
    async fn all_dropped_queries_have_a_bounded_total_budget() {
        let fixture = fixture_with_drops(vec![], vec![16, 28, 1]).await;
        let result = timeout(
            Duration::from_secs(6),
            resolve_server_addr(&fixture.dns, "endpoint.test.", 7000),
        )
        .await
        .expect("DNS resolution must leave time for connection/login");
        assert!(result.is_err());
        assert!(fixture.seen.lock().unwrap().contains(&1));
    }

    #[test]
    fn ip4p_prefix_is_exactly_eighty_bits() {
        for value in ["2001::1f90:c000:201", "2001::c000:201"] {
            assert!(is_ip4p(value.parse().unwrap()));
        }
        for value in [
            "2001:db8::1",
            "2001::1:1f90:c000:201",
            "2002::1f90:c000:201",
        ] {
            assert!(!is_ip4p(value.parse().unwrap()));
        }
    }

    #[tokio::test]
    async fn malformed_inputs_fail_without_network() {
        for host in ["", "[not-ipv6]", "bad\nhost", "bad host"] {
            assert!(resolve_server_addr("invalid DNS", host, 7000)
                .await
                .is_err());
        }
        let fixture = fixture(vec![]).await;
        assert!(resolve_server_addr(&fixture.dns, "bad\nhost", 7000)
            .await
            .is_err());
    }

    #[test]
    fn txt_size_is_bounded_before_trimming() {
        let value = format!("{}MTkyLjAuMi4xOjgwODA=", " ".repeat(1024));
        assert_eq!(parse_txt(value.as_bytes()), None);
    }

    #[tokio::test]
    async fn txt_record_count_is_bounded() {
        let mut records: Vec<_> = (0..16).map(|i| txt(&[&format!("bad{i}")])).collect();
        records.push(txt(&["MTkyLjAuMi4xOjgwODA="]));
        records.push((1, vec![192, 0, 2, 2]));
        let fixture = fixture(records).await;
        assert_eq!(
            resolve_server_addr(&fixture.dns, "endpoint.test.", 7000)
                .await
                .unwrap(),
            "192.0.2.2:7000".parse().unwrap()
        );
    }

    #[tokio::test]
    async fn ordinary_a_precedes_ipv6_and_zero_port_ip4p_is_not_an_endpoint() {
        for with_a in [true, false] {
            let mut records = vec![
                (
                    28,
                    "2001::c000:201"
                        .parse::<std::net::Ipv6Addr>()
                        .unwrap()
                        .octets()
                        .to_vec(),
                ),
                (
                    28,
                    "2001:db8::1"
                        .parse::<std::net::Ipv6Addr>()
                        .unwrap()
                        .octets()
                        .to_vec(),
                ),
            ];
            if with_a {
                records.push((1, vec![192, 0, 2, 3]));
            }
            let fixture = fixture(records).await;
            let expected = if with_a {
                "192.0.2.3:7000"
            } else {
                "[2001:db8::1]:7000"
            };
            assert_eq!(
                resolve_server_addr(&fixture.dns, "endpoint.test.", 7000)
                    .await
                    .unwrap(),
                expected.parse().unwrap()
            );
            let queries = fixture.seen.lock().unwrap();
            assert_eq!(&queries[..3], [16, 28, 1]);
        }
    }

    #[tokio::test]
    async fn separate_txt_records_are_not_joined_and_errors_do_not_echo_txt() {
        let fixture = fixture(vec![
            txt(&["MTkyLjAu"]),
            txt(&["Mi4xOjgwODA="]),
            txt(&["\r\nINJECT"]),
            (
                28,
                "2001::c000:201"
                    .parse::<std::net::Ipv6Addr>()
                    .unwrap()
                    .octets()
                    .to_vec(),
            ),
        ])
        .await;
        let error = resolve_server_addr(&fixture.dns, "endpoint.test.", 7000)
            .await
            .unwrap_err()
            .to_string();
        assert!(!error.contains("INJECT") && !error.contains(['\r', '\n']));
    }

    #[test]
    fn txt_encoding_and_endpoint_validation() {
        let expected = Some("192.0.2.1:8080".parse().unwrap());
        for value in [
            "MTkyLjAuMi4xOjgwODA=",
            "MTkyLjAuMi4xOjgwODA",
            " \t' MTkyLjAuMi4xOjgwODA= '\r\n",
            "\"MTkyLjAuMi4xOjgwODA\"",
        ] {
            assert_eq!(parse_txt(value.as_bytes()), expected, "{value:?}");
        }
        for value in [
            "[::1]:80",
            "192.0.2.1:0",
            "192.0.2.1:65536",
            "192.0.2.1: 80",
            "192.0.2.1:80\n",
            "192.0.2.1:+80",
        ] {
            let encoded = base64::engine::general_purpose::STANDARD.encode(value);
            assert_eq!(parse_txt(encoded.as_bytes()), None, "{value:?}");
        }
        for value in [
            "MTkyLjAuMi4xOjgwODB=",
            "MTkyLjAuMi4xOjgwODA==",
            "MTky=LjAuMi4xOjgwODA",
            "+-_/",
            "\"'MTkyLjAuMi4xOjgwODA='\"",
            "/w==",
        ] {
            assert_eq!(parse_txt(value.as_bytes()), None, "{value:?}");
        }
    }

    // Real UDP DNS fixture; records are raw RDATA so TXT segment boundaries survive.
    struct Fixture {
        dns: String,
        seen: std::sync::Arc<std::sync::Mutex<Vec<u16>>>,
        task: tokio::task::JoinHandle<()>,
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    async fn fixture(records: Vec<(u16, Vec<u8>)>) -> Fixture {
        fixture_with_drops(records, vec![]).await
    }

    async fn fixture_with_drops(records: Vec<(u16, Vec<u8>)>, drops: Vec<u16>) -> Fixture {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap().to_string();
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let queries = seen.clone();
        let task = tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            loop {
                let (n, peer) = socket.recv_from(&mut buf).await.unwrap();
                let mut end = 12;
                while buf[end] != 0 {
                    end += 1 + buf[end] as usize;
                }
                end += 1;
                let kind = u16::from_be_bytes([buf[end], buf[end + 1]]);
                queries.lock().unwrap().push(kind);
                if drops.contains(&kind) {
                    continue;
                }
                end += 4;
                assert!(end <= n);
                let answers: Vec<_> = records.iter().filter(|(k, _)| *k == kind).collect();
                let mut response = buf[..end].to_vec();
                response[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
                response[6..8].copy_from_slice(&(answers.len() as u16).to_be_bytes());
                response[10..12].copy_from_slice(&0u16.to_be_bytes());
                for (k, data) in answers {
                    response.extend_from_slice(&[0xc0, 0x0c]);
                    response.extend_from_slice(&k.to_be_bytes());
                    response.extend_from_slice(&[0, 1, 0, 0, 0, 60]);
                    response.extend_from_slice(&(data.len() as u16).to_be_bytes());
                    response.extend_from_slice(data);
                }
                socket.send_to(&response, peer).await.unwrap();
            }
        });
        Fixture {
            dns: addr,
            seen,
            task,
        }
    }

    fn txt(parts: &[&str]) -> (u16, Vec<u8>) {
        let mut data = Vec::new();
        for part in parts {
            data.push(part.len() as u8);
            data.extend_from_slice(part.as_bytes());
        }
        (16, data)
    }

    #[tokio::test]
    async fn txt_segments_override_configured_port() {
        let fixture = fixture(vec![txt(&["MTkyLjAu", "Mi4xOjgwODA="])]).await;
        assert_eq!(
            resolve_server_addr(&fixture.dns, "endpoint.test.", 7000)
                .await
                .unwrap(),
            "192.0.2.1:8080".parse().unwrap()
        );
        assert_eq!(*fixture.seen.lock().unwrap(), [16]);
    }

    #[tokio::test]
    async fn invalid_txt_falls_back_to_ip4p_before_a() {
        let fixture = fixture(vec![
            txt(&["invalid"]),
            (
                28,
                "2001::1f90:c000:201"
                    .parse::<std::net::Ipv6Addr>()
                    .unwrap()
                    .octets()
                    .to_vec(),
            ),
            (1, vec![192, 0, 2, 2]),
        ])
        .await;
        assert_eq!(
            resolve_server_addr(&fixture.dns, "endpoint.test.", 7000)
                .await
                .unwrap(),
            "192.0.2.1:8080".parse().unwrap()
        );
        assert_eq!(*fixture.seen.lock().unwrap(), [16, 28]);
    }

    #[tokio::test]
    async fn literals_bypass_dns() {
        for host in ["192.0.2.1", "::1", "[2001:db8::1]"] {
            let expected: std::net::IpAddr = host.trim_matches(['[', ']']).parse().unwrap();
            assert_eq!(
                resolve_server_addr("not a DNS server", host, 7000)
                    .await
                    .unwrap(),
                SocketAddr::new(expected, 7000)
            );
        }
    }
}
