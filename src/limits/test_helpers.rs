//! Fixtures that the tests of the submodules share.

use std::sync::Arc;

use super::config::{KeyPart, KeyVar, LimitZone, ReqLimit, ZoneKind};
use super::state::ZoneStore;
use crate::config::Config;
use crate::error::ConfigError;

pub(crate) const DECISION: &str = "decision {\n    backend http;\n    url http://127.0.0.1:9/decide;\n    timeout 150ms;\n    inspect_body 512;\n}\n";

/// Parses a configuration with `top` at the top level and `site` inside one site.
pub(crate) fn parse(top: &str, site: &str) -> Result<Config, ConfigError> {
    let text = format!(
        "listen 127.0.0.1:0;\n{top}\n{DECISION}default_status 421;\nsite example.com {{\n    upstream http://127.0.0.1:9;\n    {site}\n}}\n"
    );
    Config::parse_str(&text, "test.conf")
}

pub(crate) fn message(result: Result<Config, ConfigError>) -> String {
    match result {
        Ok(_) => String::from("accepted"),
        Err(error) => error.to_string(),
    }
}

pub(crate) const ONE: &str = "limit_req_zone $client_ip zone=one:10m rate=1r/s;";
pub(crate) const TWO: &str = "limit_conn_zone $client_ip zone=two:10m;";

pub(crate) fn store(capacity: usize, interval_ns: u64) -> Arc<ZoneStore> {
    Arc::new(ZoneStore::new(LimitZone {
        name: "z".to_owned(),
        key: vec![KeyPart::Var(KeyVar::ClientIp)],
        capacity,
        kind: ZoneKind::Req { interval_ns },
    }))
}

pub(crate) fn conn_store(capacity: usize) -> Arc<ZoneStore> {
    Arc::new(ZoneStore::new(LimitZone {
        name: "c".to_owned(),
        key: vec![KeyPart::Var(KeyVar::ClientIp)],
        capacity,
        kind: ZoneKind::Conn,
    }))
}

pub(crate) fn req(burst: u32, undelayed: u32) -> ReqLimit {
    ReqLimit {
        zone: 0,
        burst,
        undelayed,
    }
}
