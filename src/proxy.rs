//! Forwarding allowed requests to the site's upstream.

use std::net::IpAddr;

use bytes::Bytes;
use http::header::{CONNECTION, HeaderMap, HeaderName, HeaderValue};
use http::{Request, Response, Uri};
use http_body_util::Full;
use hyper::body::Incoming;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;

use crate::error::ProxyError;

const X_FORWARDED_FOR: HeaderName = HeaderName::from_static("x-forwarded-for");

/// Headers that describe a single connection and must not be forwarded.
const HOP_BY_HOP: [&str; 7] = [
    "connection",
    "keep-alive",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Sends requests to upstreams over a shared connection pool.
pub(crate) struct Proxy {
    client: Client<HttpConnector, Full<Bytes>>,
}

impl Proxy {
    /// Creates a proxy with an empty connection pool.
    pub(crate) fn new() -> Self {
        Self {
            client: Client::builder(TokioExecutor::new()).build_http(),
        }
    }

    /// Forwards a request with the same method, path, query and `Host` to `upstream`.
    pub(crate) async fn forward(
        &self,
        method: http::Method,
        headers: &HeaderMap,
        path_and_query: &str,
        body: Bytes,
        upstream: &Uri,
        peer: IpAddr,
    ) -> Result<Response<Incoming>, ProxyError> {
        let target: Uri = format!(
            "{}{path_and_query}",
            upstream.to_string().trim_end_matches('/')
        )
        .parse()?;
        let mut request = Request::new(Full::new(body));
        *request.method_mut() = method;
        *request.uri_mut() = target;
        *request.headers_mut() = forwarded_headers(headers, peer);
        self.client
            .request(request)
            .await
            .map_err(ProxyError::Request)
    }
}

/// Copies request headers for the upstream and appends the peer to `x-forwarded-for`.
pub(crate) fn forwarded_headers(original: &HeaderMap, peer: IpAddr) -> HeaderMap {
    let mut headers = original.clone();
    strip_hop_by_hop(&mut headers);
    let mut chain: Vec<String> = original
        .get_all(X_FORWARDED_FOR)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .map(str::to_owned)
        .collect();
    chain.push(peer.to_string());
    if let Ok(value) = HeaderValue::from_str(&chain.join(", ")) {
        headers.insert(X_FORWARDED_FOR, value);
    }
    headers
}

/// Removes hop-by-hop headers, including those named in `Connection`.
pub(crate) fn strip_hop_by_hop(headers: &mut HeaderMap) {
    let listed: Vec<String> = headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(|token| token.trim().to_ascii_lowercase())
        .filter(|token| !token.is_empty())
        .collect();
    let removed: Vec<HeaderName> = headers
        .keys()
        .filter(|name| {
            let name = name.as_str();
            HOP_BY_HOP.contains(&name) || listed.iter().any(|token| token == name)
        })
        .cloned()
        .collect();
    for name in removed {
        headers.remove(name);
    }
}
