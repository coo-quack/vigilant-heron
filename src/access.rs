//! The access list: `allow` and `deny` entries checked by client address.
//!
//! This follows nginx's `ngx_http_access_module`. The entries are checked in
//! order and the first one that covers the client decides. A client that no
//! entry covers is allowed. The client address is the one chosen by the realip
//! settings.

use std::net::IpAddr;

use crate::realip::IpNet;

/// One `allow` or `deny` line of an access list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccessEntry {
    /// True for `allow`, false for `deny`.
    pub allow: bool,
    /// The address or network the entry covers. `None` is `all`.
    pub net: Option<IpNet>,
}

impl AccessEntry {
    /// Returns true when the entry covers `ip`.
    fn covers(&self, ip: IpAddr) -> bool {
        self.net.is_none_or(|net| net.contains(ip))
    }
}

/// Returns whether an access list lets `ip` through.
///
/// The first entry that covers `ip` decides. An empty list, or one that covers
/// nothing, allows the client.
#[must_use]
pub(crate) fn permits(entries: &[AccessEntry], ip: IpAddr) -> bool {
    entries
        .iter()
        .find(|entry| entry.covers(ip))
        .is_none_or(|entry| entry.allow)
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use rstest::rstest;

    use super::*;

    fn entry(allow: bool, text: Option<&str>) -> AccessEntry {
        AccessEntry {
            allow,
            net: text.and_then(IpNet::parse),
        }
    }

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    #[test]
    fn an_empty_list_allows_every_client() {
        assert!(permits(&[], v4(203, 0, 113, 7)));
    }

    #[rstest]
    #[case::first_allow_wins_over_later_deny(
        vec![entry(true, Some("203.0.113.0/24")), entry(false, None)],
        v4(203, 0, 113, 7),
        true
    )]
    #[case::first_deny_wins_over_later_allow(
        vec![entry(false, Some("203.0.113.0/24")), entry(true, None)],
        v4(203, 0, 113, 7),
        false
    )]
    #[case::uncovered_client_is_allowed_by_default(
        vec![entry(false, Some("203.0.113.0/24"))],
        v4(198, 51, 100, 1),
        true
    )]
    #[case::deny_all_blocks_everyone(vec![entry(false, None)], v4(192, 0, 2, 1), false)]
    #[case::allow_then_deny_all_admits_only_the_network(
        vec![entry(true, Some("10.0.0.0/8")), entry(false, None)],
        v4(10, 1, 2, 3),
        true
    )]
    #[case::allow_then_deny_all_refuses_outside_the_network(
        vec![entry(true, Some("10.0.0.0/8")), entry(false, None)],
        v4(11, 1, 2, 3),
        false
    )]
    #[case::single_address_is_a_host_network(
        vec![entry(false, Some("192.0.2.9")), entry(true, None)],
        v4(192, 0, 2, 9),
        false
    )]
    #[case::ipv4_mapped_client_matches_an_ipv4_entry(
        vec![entry(false, Some("192.0.2.0/24"))],
        "::ffff:192.0.2.5".parse().unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
        false
    )]
    #[case::ipv6_entry_covers_ipv6_client(
        vec![entry(false, Some("2001:db8::/32"))],
        "2001:db8::1".parse().unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
        false
    )]
    fn the_first_matching_entry_decides(
        #[case] entries: Vec<AccessEntry>,
        #[case] client: IpAddr,
        #[case] expected: bool,
    ) {
        assert_eq!(permits(&entries, client), expected);
    }
}
