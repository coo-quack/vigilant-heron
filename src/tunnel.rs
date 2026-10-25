//! Upgraded connections: after the upstream answers 101 Switching Protocols,
//! the client connection and the upstream connection are spliced.
//!
//! Only the handshake is judged by the screening. The bytes after it are not
//! inspected: they are copied in both directions as they arrive. The tunnel
//! closes when either side closes, or when neither side has moved a byte for
//! `proxy_read_timeout`. The permits of the request's `limit_conn` zones are held
//! by the tunnel until it closes.

use std::io;
use std::sync::Arc;
use std::time::Duration;

use hyper::upgrade::OnUpgrade;
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::Instant;

use crate::limits::ConnPermit;
use crate::transport::lock;

/// Bytes copied at a time in each direction.
const PUMP_BUFFER: usize = 16 * 1024;

/// The time of the last byte copied in either direction.
#[derive(Debug)]
struct Activity(std::sync::Mutex<Instant>);

impl Activity {
    fn new() -> Self {
        Self(std::sync::Mutex::new(Instant::now()))
    }

    fn touch(&self) {
        *lock(&self.0) = Instant::now();
    }

    fn last(&self) -> Instant {
        *lock(&self.0)
    }
}

/// Waits for the client and the upstream to be upgraded, then splices them in the background.
///
/// `permits` are held until the tunnel closes, so the tunnel counts against
/// `limit_conn` while it is open. `idle` is the inactivity that closes it.
pub(crate) fn spawn(
    client: OnUpgrade,
    upstream: OnUpgrade,
    idle: Duration,
    permits: Vec<ConnPermit>,
) {
    tokio::spawn(async move {
        let _permits = permits;
        let (client, upstream) = match (client.await, upstream.await) {
            (Ok(client), Ok(upstream)) => (client, upstream),
            (Err(error), _) | (_, Err(error)) => {
                tracing::debug!(%error, "tunnel not established: an upgrade failed");
                return;
            }
        };
        splice(TokioIo::new(client), TokioIo::new(upstream), idle).await;
    });
}

/// Copies bytes both ways until one side closes or both are idle for `idle`.
pub(crate) async fn splice<A, B>(client: A, upstream: B, idle: Duration)
where
    A: AsyncRead + AsyncWrite + Unpin + Send,
    B: AsyncRead + AsyncWrite + Unpin + Send,
{
    let (client_read, client_write) = tokio::io::split(client);
    let (upstream_read, upstream_write) = tokio::io::split(upstream);
    let activity = Arc::new(Activity::new());
    let to_upstream = pump(client_read, upstream_write, Arc::clone(&activity));
    let to_client = pump(upstream_read, client_write, Arc::clone(&activity));
    tokio::select! {
        _ = to_upstream => {}
        _ = to_client => {}
        () = idle_timeout(&activity, idle) => {}
    }
}

/// Copies from `reader` to `writer` until the reader ends. The writer is shut down at the end.
async fn pump<R, W>(mut reader: R, mut writer: W, activity: Arc<Activity>) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = vec![0u8; PUMP_BUFFER];
    loop {
        let read = reader.read(&mut buffer).await?;
        if read == 0 {
            // The peer is done sending; a failed shutdown changes nothing.
            let _ = writer.shutdown().await;
            return Ok(());
        }
        activity.touch();
        let chunk = buffer.get(..read).unwrap_or_default();
        writer.write_all(chunk).await?;
        activity.touch();
    }
}

/// Returns once no byte has moved for `idle`. Each wake-up checks the latest activity again.
async fn idle_timeout(activity: &Activity, idle: Duration) {
    loop {
        let deadline = activity.last() + idle;
        if Instant::now() >= deadline {
            return;
        }
        tokio::time::sleep_until(deadline).await;
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    use super::*;

    #[tokio::test]
    async fn bytes_flow_both_ways_until_one_side_closes() {
        let (mut client_end, client_side) = duplex(1024);
        let (upstream_side, mut upstream_end) = duplex(1024);
        let tunnel = tokio::spawn(splice(client_side, upstream_side, Duration::from_secs(30)));

        client_end.write_all(b"ping").await.ok();
        let mut buf = [0u8; 4];
        upstream_end.read_exact(&mut buf).await.ok();
        assert_eq!(&buf, b"ping");

        upstream_end.write_all(b"pong").await.ok();
        client_end.read_exact(&mut buf).await.ok();
        assert_eq!(&buf, b"pong");

        drop(client_end);
        assert!(tunnel.await.is_ok());
    }

    #[tokio::test(start_paused = true)]
    async fn an_idle_tunnel_closes_after_the_timeout() {
        let (_client_end, client_side) = duplex(1024);
        let (upstream_side, _upstream_end) = duplex(1024);
        let started = Instant::now();
        splice(client_side, upstream_side, Duration::from_secs(5)).await;
        let idle_for = started.elapsed();
        assert!(
            idle_for >= Duration::from_secs(5),
            "closed after {idle_for:?}"
        );
        assert!(
            idle_for < Duration::from_secs(6),
            "closed after {idle_for:?}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn traffic_keeps_the_tunnel_open_past_one_timeout() {
        let (mut client_end, client_side) = duplex(1024);
        let (upstream_side, mut upstream_end) = duplex(1024);
        let tunnel = tokio::spawn(splice(client_side, upstream_side, Duration::from_secs(5)));
        for _ in 0..3 {
            tokio::time::sleep(Duration::from_secs(4)).await;
            client_end.write_all(b"x").await.ok();
            let mut byte = [0u8; 1];
            upstream_end.read_exact(&mut byte).await.ok();
        }
        assert!(!tunnel.is_finished(), "closed while traffic kept it busy");
        tunnel.abort();
    }
}
