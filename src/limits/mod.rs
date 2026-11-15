//! Request-rate and connection limits, with the semantics of nginx's
//! `ngx_http_limit_req_module` and `ngx_http_limit_conn_module`.
//!
//! A `limit_req_zone` names a leaky bucket per key. Each request adds one unit
//! to its key's bucket, and the bucket drains at the configured rate. A request
//! that finds the bucket above `burst` is rejected. Otherwise it passes at once,
//! or it waits until its turn when it is beyond the requests `nodelay` or
//! `delay=` allow without a wait.
//!
//! A `limit_conn_zone` counts the requests in progress per key. A request is
//! counted from the moment its header is read until its response body is done or
//! dropped.
//!
//! Zones live in the router process. A zone holds as many states as its size
//! allows, 128 bytes per `limit_req` state and 64 per `limit_conn` state, as in
//! nginx. The least recently used idle state is evicted when the zone is full.
//! When no state can be created even after eviction, the request is handled as a
//! rejection: with the configured status, or as a dry-run rejection in dry run.
//!
//! Time comes from [`tokio::time`], so tests can pause and advance it.

mod config;
mod location;
mod screen;
mod state;
#[cfg(test)]
mod test_helpers;

pub(crate) use config::{
    LIMIT_NAMES, LimitOverrides, LimitSet, LimitZone, ZONE_NAMES, build_zones,
};
pub(crate) use location::{LocationConfig, parse_location, select_location, select_locations};
pub(crate) use screen::{KeyVars, screen};
pub(crate) use state::{ConnPermit, ConnStatus, ReqStatus, ZoneStore};

#[cfg(test)]
mod tests {
    use crate::config::Config;
    use crate::error::ConfigError;

    use super::test_helpers::DECISION;

    #[test]
    fn the_example_in_the_readme_loads() -> Result<(), ConfigError> {
        let text = format!(
            "listen 127.0.0.1:0;\nlimit_req_zone $client_ip zone=perip:10m rate=10r/s;\nlimit_conn_zone $client_ip zone=conns:10m;\n{DECISION}site example.com {{\n    upstream http://upstream:80;\n\n    location = /wp-login.php {{\n        limit_req zone=perip burst=2 nodelay;\n        limit_req_status 429;\n    }}\n    location /downloads/ {{\n        limit_conn conns 4;\n    }}\n}}\n"
        );
        let config = Config::parse_str(&text, "test.conf")?;
        let site = config.sites.first().ok_or(ConfigError::Invalid {
            file: "test.conf".to_owned(),
            line: 1,
            message: "no site".to_owned(),
        })?;
        assert_eq!(site.locations.len(), 2);
        Ok(())
    }
}
