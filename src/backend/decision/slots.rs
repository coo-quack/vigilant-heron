//! The per-client limit on decision calls in flight (`max_concurrency_per_client`).

use std::net::IpAddr;
use std::sync::Arc;

/// Decision calls in flight per client address, bounded by `max_concurrency_per_client`.
///
/// A client that already holds its share is refused at once, so it cannot take the
/// global slots that other clients need. The key is the client address chosen by the
/// realip settings. A distributed attack from many addresses is not limited by this.
pub(crate) struct ClientSlots {
    /// The most calls one address may have in flight.
    limit: usize,
    /// Calls in flight per address. An address with none is removed.
    held: std::sync::Mutex<std::collections::HashMap<IpAddr, usize>>,
}

impl ClientSlots {
    /// Creates a table that allows `limit` calls per address.
    pub(crate) fn new(limit: usize) -> Arc<Self> {
        Arc::new(Self {
            limit,
            held: std::sync::Mutex::new(std::collections::HashMap::new()),
        })
    }

    /// The most calls one address may have in flight.
    pub(crate) fn limit(&self) -> usize {
        self.limit
    }

    /// Takes one call for `client`, or returns `None` when the client already holds its share.
    pub(crate) fn take(self: &Arc<Self>, client: IpAddr) -> Option<ClientSlot> {
        let mut held = self
            .held
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let count = held.entry(client).or_insert(0);
        if *count >= self.limit {
            return None;
        }
        *count += 1;
        Some(ClientSlot {
            table: Arc::clone(self),
            client,
        })
    }
}

/// One call of a client, released when dropped.
pub(crate) struct ClientSlot {
    /// The table the call was taken from.
    table: Arc<ClientSlots>,
    /// The client address that holds the call.
    client: IpAddr,
}

impl Drop for ClientSlot {
    fn drop(&mut self) {
        let mut held = self
            .table
            .held
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(count) = held.get_mut(&self.client) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                held.remove(&self.client);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::ClientSlots;

    #[test]
    fn a_client_is_refused_beyond_its_share_and_regains_it_on_drop() {
        let table = ClientSlots::new(2);
        let client = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));
        let other = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 2));
        let first = table.take(client);
        let second = table.take(client);
        assert!(first.is_some() && second.is_some());
        assert!(table.take(client).is_none());
        assert!(
            table.take(other).is_some(),
            "another client is not affected"
        );
        drop(first);
        assert!(table.take(client).is_some());
    }

    #[test]
    fn the_table_reports_the_limit_it_was_created_with() {
        assert_eq!(ClientSlots::new(3).limit(), 3);
    }

    #[test]
    fn dropping_one_of_two_calls_leaves_the_other_counted() {
        let table = ClientSlots::new(2);
        let client = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 3));
        let first = table.take(client);
        let second = table.take(client);
        drop(first);
        let third = table.take(client);
        assert!(
            third.is_some(),
            "the slot of the dropped call is free again"
        );
        assert!(
            table.take(client).is_none(),
            "the share is still two calls, and the remaining one is counted"
        );
        assert!(second.is_some());
    }
}
