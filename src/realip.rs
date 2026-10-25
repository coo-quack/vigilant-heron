//! Client address selection in the style of nginx's `realip` module.
//!
//! The configured header (`X-Real-IP` by default) is believed only when the
//! peer is a trusted proxy, listed in `real_ip_from`. Otherwise the client
//! address is the peer address. When the header comes in several lines, the
//! caller joins them in order, as nginx does, before the address is chosen.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use http::HeaderName;

/// A single address or a network in CIDR form, such as `10.0.0.0/8`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpNet {
    /// The network address.
    addr: IpAddr,
    /// Number of leading bits that must match.
    prefix: u8,
}

impl IpNet {
    /// Parses `10.0.0.0/8`, `2001:db8::/32`, or a bare address, which is a host network.
    ///
    /// Returns `None` for anything else, including a prefix longer than the address.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        let (addr_text, prefix_text) = match text.split_once('/') {
            Some((addr, prefix)) => (addr, Some(prefix)),
            None => (text, None),
        };
        let addr: IpAddr = addr_text.parse().ok()?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix_text {
            Some(text) => text.parse::<u8>().ok().filter(|p| *p <= max)?,
            None => max,
        };
        Some(Self { addr, prefix })
    }

    /// Returns true when `ip` lies inside this network.
    #[must_use]
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, normalize(ip)) {
            (IpAddr::V4(net), IpAddr::V4(candidate)) => {
                masked_v4(net, self.prefix) == masked_v4(candidate, self.prefix)
            }
            (IpAddr::V6(net), IpAddr::V6(candidate)) => {
                masked_v6(net, self.prefix) == masked_v6(candidate, self.prefix)
            }
            (IpAddr::V4(_), IpAddr::V6(_)) | (IpAddr::V6(_), IpAddr::V4(_)) => false,
        }
    }
}

/// Maps an IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) to its IPv4 form.
fn normalize(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
        IpAddr::V4(v4) => IpAddr::V4(v4),
    }
}

fn masked_v4(addr: Ipv4Addr, prefix: u8) -> u32 {
    let bits = u32::from(addr);
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix))
    };
    bits & mask
}

fn masked_v6(addr: Ipv6Addr, prefix: u8) -> u128 {
    let bits = u128::from(addr);
    let mask = if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - u32::from(prefix))
    };
    bits & mask
}

/// The settings that decide which address is the client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RealIp {
    /// Proxies whose header is believed.
    pub trusted: Vec<IpNet>,
    /// Header that carries the client address. `X-Real-IP` by default.
    pub header: HeaderName,
    /// With `real_ip_recursive on`, the address is the last one, from the right,
    /// that is not a trusted proxy.
    pub recursive: bool,
}

impl RealIp {
    /// Returns true when `ip` is a trusted proxy.
    pub(crate) fn is_trusted(&self, ip: IpAddr) -> bool {
        self.trusted.iter().any(|net| net.contains(ip))
    }

    /// Chooses the client address for a request from `peer`.
    ///
    /// A malformed header value, such as an entry that is not an address, is
    /// ignored in full, and the peer is used.
    pub(crate) fn client_ip(&self, peer: IpAddr, header_value: Option<&str>) -> IpAddr {
        let peer = normalize(peer);
        if !self.is_trusted(peer) {
            return peer;
        }
        let Some(value) = header_value else {
            return peer;
        };
        let addresses: Option<Vec<IpAddr>> = value
            .split(',')
            .map(str::trim)
            .filter(|entry| !entry.is_empty())
            .map(|entry| entry.parse::<IpAddr>().ok().map(normalize))
            .collect();
        let Some(addresses) = addresses.filter(|list| !list.is_empty()) else {
            return peer;
        };
        if !self.recursive {
            return addresses.last().copied().unwrap_or(peer);
        }
        addresses
            .iter()
            .rev()
            .find(|addr| !self.is_trusted(**addr))
            .copied()
            .or_else(|| addresses.first().copied())
            .unwrap_or(peer)
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;

    fn realip(trusted: &[&str], recursive: bool) -> RealIp {
        RealIp {
            trusted: trusted.iter().filter_map(|t| IpNet::parse(t)).collect(),
            header: HeaderName::from_static("x-real-ip"),
            recursive,
        }
    }

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
    }

    #[rstest]
    #[case::network("10.0.0.0/8", "10.200.1.2", true)]
    #[case::network_edge_outside("10.0.0.0/8", "11.0.0.0", false)]
    #[case::single_address("192.0.2.7", "192.0.2.7", true)]
    #[case::single_address_other("192.0.2.7", "192.0.2.8", false)]
    #[case::ipv6_network("2001:db8::/32", "2001:db8:1::5", true)]
    #[case::ipv6_outside("2001:db8::/32", "2001:db9::1", false)]
    #[case::mapped_peer_matches_ipv4("10.0.0.0/8", "::ffff:10.1.1.1", true)]
    #[case::zero_prefix_matches_everything("0.0.0.0/0", "203.0.113.9", true)]
    fn trusted_networks_contain_the_right_addresses(
        #[case] net: &str,
        #[case] candidate: &str,
        #[case] expected: bool,
    ) {
        let network = IpNet::parse(net);
        assert_eq!(network.map(|n| n.contains(ip(candidate))), Some(expected));
    }

    #[rstest]
    #[case::prefix_too_long("10.0.0.0/33")]
    #[case::not_an_address("example.com")]
    #[case::bad_prefix("10.0.0.0/x")]
    fn invalid_networks_are_rejected(#[case] text: &str) {
        assert_eq!(IpNet::parse(text), None);
    }

    #[test]
    fn untrusted_peer_ignores_the_header() {
        let config = realip(&["10.0.0.0/8"], false);
        assert_eq!(
            config.client_ip(ip("203.0.113.9"), Some("198.51.100.1")),
            ip("203.0.113.9")
        );
    }

    #[test]
    fn trusted_peer_uses_the_header() {
        let config = realip(&["10.0.0.0/8"], false);
        assert_eq!(
            config.client_ip(ip("10.0.0.2"), Some("198.51.100.1")),
            ip("198.51.100.1")
        );
    }

    #[test]
    fn trusted_peer_without_a_header_uses_the_peer() {
        let config = realip(&["10.0.0.0/8"], false);
        assert_eq!(config.client_ip(ip("10.0.0.2"), None), ip("10.0.0.2"));
    }

    #[test]
    fn non_recursive_takes_the_rightmost_address_of_a_list() {
        let config = realip(&["10.0.0.0/8"], false);
        assert_eq!(
            config.client_ip(ip("10.0.0.2"), Some("198.51.100.1, 10.0.0.9")),
            ip("10.0.0.9")
        );
    }

    #[test]
    fn recursive_skips_trusted_hops_from_the_right() {
        let config = realip(&["10.0.0.0/8"], true);
        assert_eq!(
            config.client_ip(ip("10.0.0.2"), Some("198.51.100.1, 10.0.0.9, 10.0.0.10")),
            ip("198.51.100.1")
        );
    }

    #[test]
    fn recursive_with_only_trusted_addresses_takes_the_leftmost() {
        let config = realip(&["10.0.0.0/8"], true);
        assert_eq!(
            config.client_ip(ip("10.0.0.2"), Some("10.0.0.5, 10.0.0.6")),
            ip("10.0.0.5")
        );
    }

    #[rstest]
    #[case::not_an_address("garbage")]
    #[case::empty_entry_only("   ")]
    #[case::one_bad_entry_spoils_the_list("198.51.100.1, nope")]
    fn malformed_values_fall_back_to_the_peer(#[case] value: &str) {
        let config = realip(&["10.0.0.0/8"], true);
        assert_eq!(
            config.client_ip(ip("10.0.0.2"), Some(value)),
            ip("10.0.0.2")
        );
    }

    #[test]
    fn ipv6_clients_work_through_a_trusted_ipv6_proxy() {
        let config = realip(&["2001:db8::/32"], false);
        assert_eq!(
            config.client_ip(ip("2001:db8::1"), Some("2600:1f18::9")),
            ip("2600:1f18::9")
        );
    }

    proptest::proptest! {
        #[test]
        fn client_selection_never_panics(value in "[0-9a-f:., x]{0,60}") {
            let config = realip(&["10.0.0.0/8"], true);
            let _ = config.client_ip(ip("10.0.0.2"), Some(&value));
        }
    }
}
