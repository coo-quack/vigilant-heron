//! Forwarding allowed requests to the site's upstream.
//!
//! Each site has its own client, so `proxy_connect_timeout` and
//! `proxy_send_timeout` can differ per site. The connection pool is per site too.

use std::error::Error as StdError;
use std::future::Future;
use std::io;
use std::net::IpAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http::header::{CONNECTION, HeaderMap, HeaderName, HeaderValue, UPGRADE};
use http::{Request, Response, Uri};
use http_body_util::combinators::UnsyncBoxBody;
use hyper::body::Incoming;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::net::TcpStream;
use tower_service::Service;

use crate::body::{BoxError, ClientBody, FaultSlot, FrameTimeout};
use crate::conf::Directive;
use crate::config::{SiteTimeouts, invalid};
use crate::error::{ConfigError, ProxyError};
use crate::transport::UpstreamIo;

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

/// The client that sends requests to one site's upstream.
pub(crate) type UpstreamClient = Client<UpstreamConnector, UnsyncBoxBody<Bytes, BoxError>>;

/// Opens upstream connections, bounding the connect time and the wait between writes.
#[derive(Clone)]
pub(crate) struct UpstreamConnector {
    http: HttpConnector,
    send_timeout: Duration,
}

impl Service<Uri> for UpstreamConnector {
    type Response = TokioIo<UpstreamIo<TcpStream>>;
    type Error = BoxError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, BoxError>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), BoxError>> {
        self.http
            .poll_ready(cx)
            .map_err(|error| -> BoxError { Box::new(error) })
    }

    fn call(&mut self, target: Uri) -> Self::Future {
        let connecting = self.http.call(target);
        let send_timeout = self.send_timeout;
        Box::pin(async move {
            let stream = connecting
                .await
                .map_err(|error| -> BoxError { Box::new(error) })?;
            Ok(TokioIo::new(UpstreamIo::new(
                stream.into_inner(),
                send_timeout,
            )))
        })
    }
}

/// Sends requests to one site's upstream over its connection pool.
pub(crate) struct Proxy {
    client: UpstreamClient,
    read_timeout: Duration,
}

impl Proxy {
    /// Creates the client for a site with its `proxy_*` timers.
    pub(crate) fn new(timeouts: &SiteTimeouts) -> Self {
        let mut http = HttpConnector::new();
        http.set_connect_timeout(Some(timeouts.proxy_connect_timeout));
        let connector = UpstreamConnector {
            http,
            send_timeout: timeouts.proxy_send_timeout,
        };
        Self {
            client: Client::builder(TokioExecutor::new()).build(connector),
            read_timeout: timeouts.proxy_read_timeout,
        }
    }

    /// The `proxy_read_timeout` of the site: the wait for a response head, and the idle limit of a tunnel.
    pub(crate) fn read_timeout(&self) -> Duration {
        self.read_timeout
    }

    /// Forwards a request with `method`, `path_and_query` and the given `headers` to `upstream`.
    ///
    /// The headers are the ones [`upstream_headers`] builds. The body is streamed:
    /// the bytes already sniffed go first, then the rest as the upstream reads
    /// them. The wait for the response head, from the start of the request, is
    /// bounded by `proxy_read_timeout`.
    ///
    /// # Errors
    ///
    /// Returns [`ProxyError::ReadTimeout`] when no response head arrives in time,
    /// [`ProxyError::Body`] when the client body fails, and the connection errors otherwise.
    pub(crate) async fn forward(
        &self,
        method: http::Method,
        headers: HeaderMap,
        path_and_query: &str,
        body: ClientBody,
        upstream: &Uri,
    ) -> Result<Response<FrameTimeout<Incoming>>, ProxyError> {
        let target: Uri = format!(
            "{}{path_and_query}",
            upstream.to_string().trim_end_matches('/')
        )
        .parse()?;
        let faults = body.fault_slot();
        let mut request = Request::new(body.into_unsync());
        *request.method_mut() = method;
        *request.uri_mut() = target;
        *request.headers_mut() = headers;
        let response =
            match tokio::time::timeout(self.read_timeout, self.client.request(request)).await {
                Ok(result) => result.map_err(|error| classify(error, &faults))?,
                Err(_elapsed) => return Err(ProxyError::ReadTimeout),
            };
        let (parts, body) = response.into_parts();
        Ok(Response::from_parts(
            parts,
            FrameTimeout::new(body, self.read_timeout),
        ))
    }
}

/// Sorts a failed upstream request into its cause. A fault of the client body wins.
fn classify(error: hyper_util::client::legacy::Error, faults: &FaultSlot) -> ProxyError {
    let fault = *faults
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(fault) = fault {
        return ProxyError::Body(fault);
    }
    let timed_out = has_timed_out(&error);
    if error.is_connect() {
        if timed_out {
            ProxyError::ConnectTimeout
        } else {
            ProxyError::Connect(error)
        }
    } else if timed_out {
        ProxyError::SendTimeout(error)
    } else {
        ProxyError::Request(error)
    }
}

/// Whether a timeout error appears anywhere in the error's chain of sources.
fn has_timed_out(error: &(dyn StdError + 'static)) -> bool {
    let mut current = Some(error);
    while let Some(next) = current {
        if next
            .downcast_ref::<io::Error>()
            .is_some_and(|io| io.kind() == io::ErrorKind::TimedOut)
        {
            return true;
        }
        current = next.source();
    }
    false
}

/// One `proxy_set_header` directive: a header name and the value template it is set to.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct HeaderOp {
    /// The header that is set or removed.
    pub(crate) name: HeaderName,
    /// The value, as literal text and variables.
    template: Vec<Part>,
}

/// One piece of a `proxy_set_header` value.
#[derive(Debug, Clone, PartialEq)]
enum Part {
    /// Text copied as written.
    Text(String),
    /// A variable, replaced with its value for each request.
    Var(Var),
}

/// The variables a `proxy_set_header` value may use.
#[derive(Debug, Clone, PartialEq)]
enum Var {
    /// The client address chosen by the realip settings.
    ClientIp,
    /// The address of the TCP peer.
    RemoteAddr,
    /// The normalized `Host` of the request.
    Host,
    /// The first host name of the site that serves the request.
    Site,
    /// The request method.
    Method,
    /// The request path, as received.
    Path,
    /// The request id, or an empty string when there is none.
    RequestId,
    /// A request header, `$http_<name>`, with underscores read as hyphens.
    Header(HeaderName),
}

/// The values of one request that `proxy_set_header` values can use.
#[derive(Debug, Clone, Copy)]
pub(crate) struct HeaderContext<'a> {
    /// The client address chosen by the realip settings.
    pub(crate) client_ip: &'a str,
    /// The address of the TCP peer.
    pub(crate) remote_addr: &'a str,
    /// The normalized `Host` of the request.
    pub(crate) host: &'a str,
    /// The site name, or an empty string.
    pub(crate) site: &'a str,
    /// The request method.
    pub(crate) method: &'a str,
    /// The request path, as received.
    pub(crate) path: &'a str,
    /// The request id, or an empty string.
    pub(crate) request_id: &'a str,
    /// The headers the client sent.
    pub(crate) headers: &'a HeaderMap,
}

impl HeaderOp {
    /// Parses `proxy_set_header <name> <value>;`. An empty value removes the header.
    ///
    /// # Errors
    ///
    /// Returns an error when the directive has no name, names a hop-by-hop
    /// header, uses an unknown variable, or has text that is not a valid header value.
    pub(crate) fn parse(directive: &Directive) -> Result<Self, ConfigError> {
        let [name, value] = directive.args.as_slice() else {
            return Err(invalid(
                directive,
                "\"proxy_set_header\" takes a header name and a value; use \"\" to remove a header",
            ));
        };
        let header = HeaderName::from_bytes(name.as_bytes()).map_err(|_| {
            invalid(
                directive,
                format!("\"proxy_set_header\" is not a header name: {name}"),
            )
        })?;
        if HOP_BY_HOP.contains(&header.as_str()) {
            return Err(invalid(
                directive,
                format!("\"proxy_set_header\" cannot set the hop-by-hop header {name}"),
            ));
        }
        let template = parse_template(directive, value)?;
        Ok(Self {
            name: header,
            template,
        })
    }

    /// The value for one request. An empty value removes the header.
    fn render(&self, ctx: &HeaderContext<'_>) -> String {
        let mut value = String::new();
        for part in &self.template {
            match part {
                Part::Text(text) => value.push_str(text),
                Part::Var(var) => value.push_str(var_value(var, ctx)),
            }
        }
        value
    }
}

/// Splits a value into text and `$variable` or `${variable}` parts, and checks each variable.
fn parse_template(directive: &Directive, value: &str) -> Result<Vec<Part>, ConfigError> {
    let mut parts = Vec::new();
    let mut text = String::new();
    let mut rest = value;
    while let Some(position) = rest.find('$') {
        text.push_str(rest.get(..position).unwrap_or_default());
        let after = rest.get(position + 1..).unwrap_or_default();
        let (name, consumed) = if let Some(braced) = after.strip_prefix('{') {
            let end = braced.find('}').ok_or_else(|| {
                invalid(
                    directive,
                    "\"proxy_set_header\" has a \"${\" without a closing brace",
                )
            })?;
            (braced.get(..end).unwrap_or_default(), end + 3)
        } else {
            let length = after
                .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .unwrap_or(after.len());
            (after.get(..length).unwrap_or_default(), length + 1)
        };
        if !text.is_empty() {
            parts.push(Part::Text(std::mem::take(&mut text)));
        }
        parts.push(Part::Var(variable(directive, name)?));
        rest = rest.get(position + consumed..).unwrap_or_default();
    }
    text.push_str(rest);
    if !text.is_empty() {
        parts.push(Part::Text(text));
    }
    for part in &parts {
        if let Part::Text(literal) = part
            && HeaderValue::from_str(literal).is_err()
        {
            return Err(invalid(
                directive,
                "\"proxy_set_header\" value is not a valid header value",
            ));
        }
    }
    Ok(parts)
}

/// Reads the name of one variable.
fn variable(directive: &Directive, name: &str) -> Result<Var, ConfigError> {
    let known = match name {
        "client_ip" => Some(Var::ClientIp),
        "remote_addr" => Some(Var::RemoteAddr),
        "host" => Some(Var::Host),
        "site" => Some(Var::Site),
        "method" => Some(Var::Method),
        "path" => Some(Var::Path),
        "request_id" => Some(Var::RequestId),
        _ => None,
    };
    if let Some(var) = known {
        return Ok(var);
    }
    if let Some(header) = name.strip_prefix("http_").filter(|rest| !rest.is_empty()) {
        let header_name = header.replace('_', "-");
        return HeaderName::from_bytes(header_name.as_bytes())
            .map(Var::Header)
            .map_err(|_| {
                invalid(
                    directive,
                    format!("\"proxy_set_header\" variable ${name} is not a header name"),
                )
            });
    }
    Err(invalid(
        directive,
        format!("\"proxy_set_header\" has an unknown variable ${name}"),
    ))
}

/// The text a variable stands for in one request.
fn var_value<'a>(var: &Var, ctx: &HeaderContext<'a>) -> &'a str {
    match var {
        Var::ClientIp => ctx.client_ip,
        Var::RemoteAddr => ctx.remote_addr,
        Var::Host => ctx.host,
        Var::Site => ctx.site,
        Var::Method => ctx.method,
        Var::Path => ctx.path,
        Var::RequestId => ctx.request_id,
        Var::Header(name) => ctx
            .headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default(),
    }
}

/// Builds the headers sent upstream: the client's headers without hop-by-hop
/// ones, with the peer appended to `x-forwarded-for`, then each `proxy_set_header`
/// applied in order. A header whose value is empty, or cannot be a header value,
/// is removed.
pub(crate) fn upstream_headers(
    original: &HeaderMap,
    peer: IpAddr,
    ops: &[HeaderOp],
    ctx: &HeaderContext<'_>,
) -> HeaderMap {
    let mut headers = forwarded_headers(original, peer);
    for op in ops {
        let value = op.render(ctx);
        match HeaderValue::from_str(&value) {
            Ok(value) if !value.is_empty() => {
                headers.insert(op.name.clone(), value);
            }
            _ => {
                headers.remove(&op.name);
            }
        }
    }
    headers
}

/// The `Upgrade` value of a request that asks to switch protocols: its `Connection`
/// header lists `upgrade` and it has a non-empty `Upgrade` header.
pub(crate) fn upgrade_request(headers: &HeaderMap) -> Option<HeaderValue> {
    let asks = headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(|token| token.trim().eq_ignore_ascii_case("upgrade"));
    if !asks {
        return None;
    }
    headers
        .get(UPGRADE)
        .filter(|value| !value.is_empty())
        .cloned()
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

#[cfg(test)]
mod header_tests {
    use std::net::IpAddr;

    use http::{HeaderMap, HeaderValue};
    use rstest::rstest;

    use super::*;
    use crate::conf::parse_source;
    use crate::error::ConfigError;

    /// Parses one `proxy_set_header` line.
    fn op(line: &str) -> Result<HeaderOp, ConfigError> {
        let directives = parse_source(line, "header.conf")?;
        let first = directives.first().ok_or_else(|| ConfigError::Invalid {
            file: "header.conf".to_owned(),
            line: 1,
            message: "no directive".to_owned(),
        })?;
        HeaderOp::parse(first)
    }

    /// The TCP peer used by these tests.
    fn peer_addr() -> IpAddr {
        IpAddr::from([10, 0, 0, 2])
    }

    fn context(headers: &HeaderMap) -> HeaderContext<'_> {
        HeaderContext {
            client_ip: "203.0.113.7",
            remote_addr: "10.0.0.2",
            host: "example.com",
            site: "example.com",
            method: "GET",
            path: "/shop/item",
            request_id: "req-1",
            headers,
        }
    }

    #[rstest]
    #[case::plain("X-Real-IP $client_ip")]
    #[case::braced("X-Proto \"${http_x_forwarded_proto}\"")]
    #[case::text_around_variable("X-Note id-$request_id-end")]
    #[case::remove("X-Remove \"\"")]
    #[case::every_variable("X-All \"$remote_addr $host $site $method $path $request_id\"")]
    fn valid_set_header_lines_parse(#[case] line: &str) {
        assert!(op(&format!("proxy_set_header {line};")).is_ok());
    }

    #[rstest]
    #[case::connection("Connection close")]
    #[case::upgrade("Upgrade websocket")]
    #[case::keep_alive("Keep-Alive timeout=5")]
    #[case::transfer_encoding("Transfer-Encoding chunked")]
    #[case::te("TE trailers")]
    fn hop_by_hop_headers_cannot_be_set(#[case] line: &str) {
        let result = op(&format!("proxy_set_header {line};"));
        assert!(
            matches!(&result, Err(ConfigError::Invalid { message, .. }) if message.contains("hop-by-hop")),
            "{result:?}"
        );
    }

    #[rstest]
    #[case::unknown_variable("X-A $nope")]
    #[case::empty_variable("X-A $")]
    #[case::empty_braces("X-A ${}")]
    #[case::unclosed_braces("X-A ${client_ip")]
    #[case::cookie_variable_is_not_a_variable("X-A $http_")]
    #[case::bad_header_name("X Name value")]
    #[case::no_value("X-Only")]
    #[case::control_character_in_text("X-A bad\u{1}value")]
    fn bad_set_header_lines_are_rejected(#[case] line: &str) {
        assert!(op(&format!("proxy_set_header {line};")).is_err());
    }

    #[test]
    fn variables_take_their_values_from_the_request() -> Result<(), ConfigError> {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-proto", HeaderValue::from_static("https"));
        let ctx = context(&headers);
        let ops = [
            op("proxy_set_header X-Real-IP $client_ip;")?,
            op("proxy_set_header X-Proto \"${http_x_forwarded_proto}\";")?,
            op("proxy_set_header X-Note $method-$path-$request_id-$site-$remote_addr;")?,
        ];
        let out = upstream_headers(&HeaderMap::new(), peer_addr(), &ops, &ctx);
        assert_eq!(
            out.get("x-real-ip").map(HeaderValue::as_bytes),
            Some(&b"203.0.113.7"[..])
        );
        assert_eq!(
            out.get("x-proto").map(HeaderValue::as_bytes),
            Some(&b"https"[..])
        );
        assert_eq!(
            out.get("x-note").map(HeaderValue::as_bytes),
            Some(&b"GET-/shop/item-req-1-example.com-10.0.0.2"[..])
        );
        Ok(())
    }

    #[test]
    fn an_empty_value_removes_the_header_the_client_sent() -> Result<(), ConfigError> {
        let mut original = HeaderMap::new();
        original.insert("x-debug", HeaderValue::from_static("1"));
        let headers = HeaderMap::new();
        let ctx = context(&headers);
        let ops = [op("proxy_set_header X-Debug \"\";")?];
        let out = upstream_headers(&original, peer_addr(), &ops, &ctx);
        assert!(!out.contains_key("x-debug"));
        Ok(())
    }

    #[test]
    fn a_variable_with_no_value_removes_the_header() -> Result<(), ConfigError> {
        let headers = HeaderMap::new();
        let ctx = context(&headers);
        let ops = [op("proxy_set_header X-Proto $http_x_forwarded_proto;")?];
        let out = upstream_headers(&HeaderMap::new(), peer_addr(), &ops, &ctx);
        assert!(!out.contains_key("x-proto"));
        Ok(())
    }

    #[test]
    fn without_operations_the_peer_is_appended_to_x_forwarded_for() {
        let mut original = HeaderMap::new();
        original.insert("x-forwarded-for", HeaderValue::from_static("198.51.100.1"));
        let headers = HeaderMap::new();
        let ctx = context(&headers);
        let out = upstream_headers(&original, peer_addr(), &[], &ctx);
        assert_eq!(
            out.get("x-forwarded-for").map(HeaderValue::as_bytes),
            Some(&b"198.51.100.1, 10.0.0.2"[..])
        );
    }

    #[test]
    fn an_operation_can_replace_x_forwarded_for() -> Result<(), ConfigError> {
        let headers = HeaderMap::new();
        let ctx = context(&headers);
        let ops = [op("proxy_set_header X-Forwarded-For $client_ip;")?];
        let out = upstream_headers(&HeaderMap::new(), peer_addr(), &ops, &ctx);
        assert_eq!(
            out.get("x-forwarded-for").map(HeaderValue::as_bytes),
            Some(&b"203.0.113.7"[..])
        );
        Ok(())
    }

    #[rstest]
    #[case::upgrade_listed("upgrade", "websocket", true)]
    #[case::listed_among_others("keep-alive, Upgrade", "websocket", true)]
    #[case::no_connection_upgrade("keep-alive", "websocket", false)]
    #[case::upgrade_without_header("upgrade", "", false)]
    fn upgrade_requests_need_both_headers(
        #[case] connection: &str,
        #[case] upgrade: &str,
        #[case] expected: bool,
    ) {
        let mut headers = HeaderMap::new();
        headers.insert(
            CONNECTION,
            HeaderValue::from_str(connection).unwrap_or_else(|_| HeaderValue::from_static("")),
        );
        if !upgrade.is_empty() {
            headers.insert(UPGRADE, HeaderValue::from_static("websocket"));
        }
        assert_eq!(upgrade_request(&headers).is_some(), expected);
    }
}
