//! The state of a zone: the table of keys with its eviction, and the results of a
//! `limit_req` and a `limit_conn` check.

use std::collections::hash_map::RandomState;
use std::collections::{BTreeMap, HashMap};
use std::hash::BuildHasher;
use std::sync::Arc;
use std::time::Duration;

use tokio::time::Instant;

use super::config::{LimitZone, ReqLimit, ZoneKind};
use crate::sync::lock;

/// Units of one request in a bucket. A request drains in `interval` nanoseconds.
const UNITS_PER_REQUEST: u64 = 1000;

/// The state of one zone key, shared by the requests that use it.
#[derive(Debug)]
struct Entry {
    /// Recency stamp, the key in the zone's LRU order.
    stamp: u64,
    /// Bucket content in units of 1/1000 request, as of `last`.
    excess: u64,
    /// When `excess` was last accounted.
    last: Instant,
    /// Delayed requests waiting (`limit_req`) or requests in progress (`limit_conn`).
    active: u32,
}

/// A fixed-size digest of a rendered limit key, which names the key's state.
type KeyDigest = u128;

/// The states of a zone, with least-recently-used order.
///
/// The states are keyed by a digest of the rendered key, not by the key text.
/// The key comes from the request, so its length is up to the client; a digest
/// has a fixed size, which keeps the memory of a zone bounded by its declared
/// size whatever the keys are. The digest uses two hashers with random keys
/// chosen when the zone is created, so a client cannot find two keys that share
/// a state.
#[derive(Debug)]
struct Table {
    capacity: usize,
    hashers: (RandomState, RandomState),
    entries: HashMap<KeyDigest, Entry>,
    order: BTreeMap<u64, KeyDigest>,
    clock: u64,
}

/// No state could be created: every state of the zone is in use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Exhausted;

impl Table {
    fn new(capacity: usize) -> Self {
        Self {
            capacity,
            hashers: (RandomState::new(), RandomState::new()),
            entries: HashMap::new(),
            order: BTreeMap::new(),
            clock: 0,
        }
    }

    /// The digest of a rendered key. Two 64-bit hashes with independent random
    /// keys make one 128-bit value, which a client cannot match with another key
    /// in practice.
    fn digest(&self, key: &str) -> KeyDigest {
        let high = u128::from(self.hashers.0.hash_one(key));
        let low = u128::from(self.hashers.1.hash_one(key));
        (high << 64) | low
    }

    /// Returns the state of `key`, creating it, and marks it most recently used.
    fn entry(&mut self, key: KeyDigest, now: Instant) -> Result<&mut Entry, Exhausted> {
        match self.entries.get(&key).map(|entry| entry.stamp) {
            Some(stamp) => {
                self.order.remove(&stamp);
            }
            None => {
                if self.entries.len() >= self.capacity {
                    self.evict()?;
                }
            }
        }
        self.clock = self.clock.saturating_add(1);
        let stamp = self.clock;
        self.order.insert(stamp, key);
        let entry = self.entries.entry(key).or_insert(Entry {
            stamp,
            excess: 0,
            last: now,
            active: 0,
        });
        entry.stamp = stamp;
        Ok(entry)
    }

    /// Removes the least recently used state that is not in use.
    fn evict(&mut self) -> Result<(), Exhausted> {
        let victim = self
            .order
            .iter()
            .find(|(_, key)| {
                self.entries
                    .get(*key)
                    .is_some_and(|entry| entry.active == 0)
            })
            .map(|(stamp, key)| (*stamp, *key));
        let (stamp, key) = victim.ok_or(Exhausted)?;
        self.order.remove(&stamp);
        self.entries.remove(&key);
        Ok(())
    }

    fn remove(&mut self, key: KeyDigest) {
        if let Some(entry) = self.entries.remove(&key) {
            self.order.remove(&entry.stamp);
        }
    }
}

/// A zone defined in the configuration, with its runtime states.
#[derive(Debug)]
pub(crate) struct ZoneStore {
    pub(crate) def: LimitZone,
    /// Drain time of one request, for `limit_req` zones.
    interval_ns: Option<u64>,
    /// The counted state. A reloaded configuration shares it with the zone it replaces.
    table: Arc<std::sync::Mutex<Table>>,
}

impl ZoneStore {
    /// Creates the empty state of `def`.
    pub(crate) fn new(def: LimitZone) -> Self {
        let table = Arc::new(std::sync::Mutex::new(Table::new(def.capacity)));
        Self::with_table(def, table)
    }

    /// Creates the zone `def` on the state of `previous`, which a reload keeps when the
    /// name and size are the same. The definition itself is the new one.
    pub(crate) fn sharing(def: LimitZone, previous: &Self) -> Self {
        Self::with_table(def, Arc::clone(&previous.table))
    }

    fn with_table(def: LimitZone, table: Arc<std::sync::Mutex<Table>>) -> Self {
        let interval_ns = match def.kind {
            ZoneKind::Req { interval_ns } => Some(interval_ns),
            ZoneKind::Conn => None,
        };
        Self {
            def,
            interval_ns,
            table,
        }
    }

    /// The number of states the zone holds, which is its size.
    pub(crate) fn capacity(&self) -> usize {
        self.def.capacity
    }

    /// Accounts one request against a `limit_req` zone.
    ///
    /// The bucket drains by the time since its last accounting. A request is
    /// rejected when the bucket holds more than `burst` requests. Otherwise it
    /// goes into the bucket, and waits when the bucket already holds more than
    /// the `undelayed` requests. In dry run nothing is rejected or waited for,
    /// and the request is accounted as if it passed.
    ///
    /// # Errors
    ///
    /// Returns [`Exhausted`] when the zone has no free state.
    pub(crate) fn admit(
        self: &Arc<Self>,
        key: &str,
        limit: &ReqLimit,
        dry_run: bool,
        now: Instant,
    ) -> Result<Admission, Exhausted> {
        let Some(interval_ns) = self.interval_ns else {
            // Configuration binds `limit_req` only to request-rate zones.
            return Ok(Admission::passed());
        };
        let mut table = lock(&self.table);
        let digest = table.digest(key);
        let entry = table.entry(digest, now)?;
        let elapsed = now.saturating_duration_since(entry.last).as_nanos();
        let drained =
            elapsed.saturating_mul(u128::from(UNITS_PER_REQUEST)) / u128::from(interval_ns);
        let drained = u64::try_from(drained).unwrap_or(u64::MAX);
        let excess = entry.excess.saturating_sub(drained);
        let burst_units = u64::from(limit.burst) * UNITS_PER_REQUEST;
        if excess > burst_units {
            if dry_run {
                entry.excess = excess.saturating_add(UNITS_PER_REQUEST);
                entry.last = now;
                return Ok(Admission {
                    status: ReqStatus::RejectedDryRun,
                    wait: Duration::ZERO,
                    pending: None,
                });
            }
            return Ok(Admission {
                status: ReqStatus::Rejected,
                wait: Duration::ZERO,
                pending: None,
            });
        }
        let undelayed_units = u64::from(limit.undelayed) * UNITS_PER_REQUEST;
        let over = u128::from(excess.saturating_sub(undelayed_units));
        let wait_nanos =
            over.saturating_mul(u128::from(interval_ns)) / u128::from(UNITS_PER_REQUEST);
        let wait = Duration::from_nanos(u64::try_from(wait_nanos).unwrap_or(u64::MAX));
        entry.excess = excess.saturating_add(UNITS_PER_REQUEST);
        entry.last = now;
        if wait.is_zero() {
            return Ok(Admission::passed());
        }
        if dry_run {
            return Ok(Admission {
                status: ReqStatus::DelayedDryRun,
                wait: Duration::ZERO,
                pending: None,
            });
        }
        entry.active = entry.active.saturating_add(1);
        Ok(Admission {
            status: ReqStatus::Delayed,
            wait,
            pending: Some(Pending {
                zone: Arc::clone(self),
                digest,
            }),
        })
    }

    /// Counts one request in progress for a `limit_conn` zone.
    ///
    /// A request beyond `max` is rejected and not counted, unless the zone is in
    /// dry run, where it is counted and reported as rejected in dry run.
    ///
    /// # Errors
    ///
    /// Returns [`Exhausted`] when the zone has no free state.
    pub(crate) fn acquire(
        self: &Arc<Self>,
        key: &str,
        max: u32,
        dry_run: bool,
        now: Instant,
    ) -> Result<ConnAdmission, Exhausted> {
        let mut table = lock(&self.table);
        let digest = table.digest(key);
        let entry = table.entry(digest, now)?;
        let over = entry.active >= max;
        if over && !dry_run {
            if entry.active == 0 {
                table.remove(digest);
            }
            return Ok(ConnAdmission {
                status: ConnStatus::Rejected,
                permit: None,
            });
        }
        entry.active = entry.active.saturating_add(1);
        Ok(ConnAdmission {
            status: if over {
                ConnStatus::RejectedDryRun
            } else {
                ConnStatus::Passed
            },
            permit: Some(ConnPermit {
                zone: Arc::clone(self),
                digest,
            }),
        })
    }

    /// Releases one count of `key`. A `limit_conn` state with no requests left is removed.
    fn release(&self, digest: KeyDigest) {
        let remove_idle = matches!(self.def.kind, ZoneKind::Conn);
        let mut table = lock(&self.table);
        let idle = match table.entries.get_mut(&digest) {
            Some(entry) => {
                entry.active = entry.active.saturating_sub(1);
                entry.active == 0
            }
            None => false,
        };
        if idle && remove_idle {
            table.remove(digest);
        }
    }

    /// Name of the zone, for log lines.
    pub(crate) fn name(&self) -> &str {
        &self.def.name
    }
}

/// Outcome of a `limit_req` check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum ReqStatus {
    /// Passed at once.
    Passed,
    /// Passed after a wait.
    Delayed,
    /// Rejected.
    Rejected,
    /// Would have waited, in dry run.
    DelayedDryRun,
    /// Would have been rejected, in dry run.
    RejectedDryRun,
}

impl ReqStatus {
    /// The value of `$limit_req_status`.
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Passed => "PASSED",
            Self::Delayed => "DELAYED",
            Self::Rejected => "REJECTED",
            Self::DelayedDryRun => "DELAYED_DRY_RUN",
            Self::RejectedDryRun => "REJECTED_DRY_RUN",
        }
    }
}

/// Outcome of a `limit_conn` check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum ConnStatus {
    /// Counted and passed.
    Passed,
    /// Rejected, not counted.
    Rejected,
    /// Would have been rejected, in dry run; counted.
    RejectedDryRun,
}

impl ConnStatus {
    /// The value of `$limit_conn_status`.
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Passed => "PASSED",
            Self::Rejected => "REJECTED",
            Self::RejectedDryRun => "REJECTED_DRY_RUN",
        }
    }
}

/// The result of one `limit_req` check.
#[derive(Debug)]
pub(crate) struct Admission {
    /// What happened to the request.
    pub(crate) status: ReqStatus,
    /// How long the request waits before it goes on.
    pub(crate) wait: Duration,
    /// Keeps the state from being evicted while the request waits.
    pub(crate) pending: Option<Pending>,
}

impl Admission {
    fn passed() -> Self {
        Self {
            status: ReqStatus::Passed,
            wait: Duration::ZERO,
            pending: None,
        }
    }
}

/// A delayed request, which holds its state until it is released.
#[derive(Debug)]
pub(crate) struct Pending {
    zone: Arc<ZoneStore>,
    digest: KeyDigest,
}

impl Drop for Pending {
    fn drop(&mut self) {
        self.zone.release(self.digest);
    }
}

/// The result of one `limit_conn` check.
#[derive(Debug)]
pub(crate) struct ConnAdmission {
    /// What happened to the request.
    pub(crate) status: ConnStatus,
    pub(crate) permit: Option<ConnPermit>,
}

/// One request counted in a `limit_conn` zone. Dropping it releases the count.
#[derive(Debug)]
pub(crate) struct ConnPermit {
    zone: Arc<ZoneStore>,
    digest: KeyDigest,
}

impl Drop for ConnPermit {
    fn drop(&mut self) {
        self.zone.release(self.digest);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use proptest::prelude::*;
    use rstest::rstest;
    use tokio::time::Instant;

    use super::*;
    use crate::limits::test_helpers::{conn_store, req, store};

    #[test]
    fn a_key_digest_uses_both_halves_of_its_128_bits() {
        let table = Table::new(1);
        let high_half_used = (0..16).any(|n| table.digest(&format!("key-{n}")) >> 64 != 0);
        assert!(high_half_used);
    }

    /// Admits one request per arrival offset (ms from `base`) and returns each outcome with its wait in ms.
    fn run(
        zone: &Arc<ZoneStore>,
        limit: &ReqLimit,
        dry: bool,
        arrivals: &[u64],
    ) -> Vec<(ReqStatus, u128)> {
        let base = Instant::now();
        let mut held = Vec::new();
        let mut outcomes = Vec::new();
        for ms in arrivals {
            let now = base + Duration::from_millis(*ms);
            let admission = zone.admit("k", limit, dry, now).ok();
            outcomes.push(match admission {
                Some(admission) => {
                    let outcome = (admission.status, admission.wait.as_millis());
                    held.push(admission);
                    outcome
                }
                None => (ReqStatus::Rejected, 0),
            });
        }
        outcomes
    }

    #[rstest]
    // One request per second, no burst: the second immediate request is rejected.
    #[case(1000, 0, 0, &[0, 0, 1000, 1000], &[(ReqStatus::Passed, 0), (ReqStatus::Rejected, 0), (ReqStatus::Passed, 0), (ReqStatus::Rejected, 0)])]
    // Burst 2 with nodelay: three at once pass, the fourth is rejected.
    #[case(1000, 2, 2, &[0, 0, 0, 0], &[(ReqStatus::Passed, 0), (ReqStatus::Passed, 0), (ReqStatus::Passed, 0), (ReqStatus::Rejected, 0)])]
    // Burst 2 without nodelay: the excess requests wait one more second each.
    #[case(1000, 2, 0, &[0, 0, 0, 0], &[(ReqStatus::Passed, 0), (ReqStatus::Delayed, 1000), (ReqStatus::Delayed, 2000), (ReqStatus::Rejected, 0)])]
    // Burst 2 with delay=1: one excess request passes at once, the next waits.
    #[case(1000, 2, 1, &[0, 0, 0, 0], &[(ReqStatus::Passed, 0), (ReqStatus::Passed, 0), (ReqStatus::Delayed, 1000), (ReqStatus::Rejected, 0)])]
    // The bucket drains: after one second a request fits again.
    #[case(1000, 2, 2, &[0, 0, 0, 0, 1000], &[(ReqStatus::Passed, 0), (ReqStatus::Passed, 0), (ReqStatus::Passed, 0), (ReqStatus::Rejected, 0), (ReqStatus::Passed, 0)])]
    // 60 requests per minute is one per second.
    #[case(1000, 0, 0, &[0, 500, 1000], &[(ReqStatus::Passed, 0), (ReqStatus::Rejected, 0), (ReqStatus::Passed, 0)])]
    fn leaky_bucket_follows_nginx(
        #[case] rate: u64,
        #[case] burst: u32,
        #[case] undelayed: u32,
        #[case] arrivals: &[u64],
        #[case] expected: &[(ReqStatus, u128)],
    ) {
        // `rate` is the drain time of one request in milliseconds: 1000 is one request per second.
        let zone = store(100, rate * 1_000_000);
        let outcomes = run(&zone, &req(burst, undelayed), false, arrivals);
        assert_eq!(outcomes, expected);
    }

    #[test]
    fn a_dry_run_accounts_without_rejecting_or_waiting() {
        let zone = store(100, 1_000_000_000);
        let outcomes = run(&zone, &req(0, 0), true, &[0, 0, 0]);
        assert_eq!(
            outcomes,
            vec![
                (ReqStatus::Passed, 0),
                (ReqStatus::RejectedDryRun, 0),
                (ReqStatus::RejectedDryRun, 0),
            ]
        );
        let zone = store(100, 1_000_000_000);
        let outcomes = run(&zone, &req(2, 0), true, &[0, 0, 0, 0]);
        assert_eq!(outcomes.get(1).map(|o| o.0), Some(ReqStatus::DelayedDryRun));
        assert_eq!(outcomes.get(1).map(|o| o.1), Some(0));
    }

    #[test]
    fn a_full_zone_evicts_the_least_recently_used_idle_state() -> Result<(), Exhausted> {
        let zone = store(2, 1_000_000_000);
        let base = Instant::now();
        let limit = req(0, 0);
        let mut keep = Vec::new();
        for key in ["a", "b"] {
            keep.push(
                zone.admit(key, &limit, false, base)
                    .map_err(|_| Exhausted)?,
            );
        }
        // "a" is the least recently used, so the third key takes its state.
        let third = zone
            .admit("c", &limit, false, base)
            .map_err(|_| Exhausted)?;
        assert_eq!(third.status, ReqStatus::Passed);
        // "b" still has its state, so its bucket is full.
        let b_again = zone.admit("b", &limit, false, base);
        assert!(matches!(b_again, Ok(ref a) if a.status == ReqStatus::Rejected));
        // "a" lost its state, so it starts with an empty bucket and passes again.
        let again = zone
            .admit("a", &limit, false, base)
            .map_err(|_| Exhausted)?;
        assert_eq!(again.status, ReqStatus::Passed);
        Ok(())
    }

    #[test]
    fn a_zone_with_only_delayed_states_is_exhausted() {
        let zone = store(1, 1_000_000_000);
        let base = Instant::now();
        let limit = req(1, 0);
        let first = zone.admit("a", &limit, false, base);
        let second = zone.admit("a", &limit, false, base);
        assert!(matches!(first, Ok(ref a) if a.status == ReqStatus::Passed));
        assert!(matches!(second, Ok(ref a) if a.status == ReqStatus::Delayed));
        // The only state is held by a delayed request, so a new key has nowhere to go.
        assert!(zone.admit("b", &limit, false, base).is_err());
        drop(second);
        assert!(zone.admit("b", &limit, false, base).is_ok());
    }

    #[test]
    fn a_connection_limit_counts_requests_until_their_permit_is_dropped() {
        let zone = conn_store(10);
        let now = Instant::now();
        let first = zone.acquire("k", 1, false, now).ok();
        let second = zone.acquire("k", 1, false, now).ok();
        assert_eq!(first.as_ref().map(|a| a.status), Some(ConnStatus::Passed));
        assert_eq!(
            second.as_ref().map(|a| a.status),
            Some(ConnStatus::Rejected)
        );
        assert!(second.is_some_and(|a| a.permit.is_none()));
        let kept = zone.acquire("k", 1, false, now).ok();
        assert_eq!(kept.as_ref().map(|a| a.status), Some(ConnStatus::Rejected));
        drop(first);
        let third = zone.acquire("k", 1, false, now).ok();
        assert_eq!(third.map(|a| a.status), Some(ConnStatus::Passed));
    }

    #[test]
    fn a_connection_count_is_kept_while_another_request_of_its_key_is_in_progress() {
        let zone = conn_store(10);
        let now = Instant::now();
        let first = zone.acquire("k", 2, false, now).ok();
        let second = zone.acquire("k", 2, false, now).ok();
        assert_eq!(second.as_ref().map(|a| a.status), Some(ConnStatus::Passed));
        drop(first);
        // One request is still in progress, so one more fits and then the limit holds.
        let third = zone.acquire("k", 2, false, now).ok();
        assert_eq!(third.as_ref().map(|a| a.status), Some(ConnStatus::Passed));
        let fourth = zone.acquire("k", 2, false, now).ok();
        assert_eq!(fourth.map(|a| a.status), Some(ConnStatus::Rejected));
    }

    #[test]
    fn zone_memory_does_not_grow_with_key_length() {
        // Two states of a zone of two, with keys of 8,000 bytes each.
        let zone = store(2, 1_000_000_000);
        let now = Instant::now();
        let limit = req(5, 5);
        let long_a = "a".repeat(8_000);
        let long_b = "b".repeat(8_000);
        let long_c = "c".repeat(8_000);
        for key in [&long_a, &long_b] {
            let status = zone.admit(key, &limit, false, now).ok().map(|a| a.status);
            assert_eq!(status, Some(ReqStatus::Passed));
        }
        {
            let table = lock(&zone.table);
            // Each state is ordered by a fixed-size digest, not by the key text.
            let digests: Vec<KeyDigest> = table.order.values().copied().collect();
            assert_eq!(digests.len(), 2);
            assert!(digests.contains(&table.digest(&long_a)));
            assert!(digests.contains(&table.digest(&long_b)));
        }
        // A third long key evicts the least recently used state; the zone stays at two.
        let status = zone
            .admit(&long_c, &limit, false, now)
            .ok()
            .map(|a| a.status);
        assert_eq!(status, Some(ReqStatus::Passed));
        let table = lock(&zone.table);
        assert_eq!(table.entries.len(), 2);
        assert!(!table.entries.contains_key(&table.digest(&long_a)));
        assert!(table.entries.contains_key(&table.digest(&long_c)));
    }

    #[test]
    fn distinct_keys_keep_distinct_states_with_digests() {
        let zone = store(10, 1_000_000_000);
        let now = Instant::now();
        // Burst and undelayed are zero: a second request in the same instant is rejected.
        let limit = req(0, 0);
        let long = "x".repeat(8_000);
        let near = format!("{}y", "x".repeat(7_999));
        let keys = [
            "k1",
            "k2",
            "k1",
            long.as_str(),
            near.as_str(),
            long.as_str(),
        ];
        let mut statuses = Vec::new();
        for key in keys {
            statuses.push(zone.admit(key, &limit, false, now).ok().map(|a| a.status));
        }
        assert_eq!(
            statuses,
            vec![
                Some(ReqStatus::Passed),
                Some(ReqStatus::Passed),
                Some(ReqStatus::Rejected),
                Some(ReqStatus::Passed),
                Some(ReqStatus::Passed),
                Some(ReqStatus::Rejected),
            ]
        );
    }

    #[test]
    fn an_idle_connection_state_is_removed_and_a_dry_run_still_counts() {
        let zone = conn_store(10);
        let now = Instant::now();
        let first = zone.acquire("k", 1, false, now).ok();
        let over = zone.acquire("k", 1, true, now).ok();
        assert_eq!(
            over.as_ref().map(|a| a.status),
            Some(ConnStatus::RejectedDryRun)
        );
        drop(over);
        drop(first);
        let table_len = lock(&zone.table).entries.len();
        assert_eq!(table_len, 0);
    }

    #[test]
    fn a_connection_zone_full_of_requests_in_progress_is_exhausted() {
        let zone = conn_store(1);
        let now = Instant::now();
        let held = zone.acquire("a", 5, false, now).ok();
        assert!(held.is_some());
        assert!(zone.acquire("b", 5, false, now).is_err());
    }

    proptest! {
        /// Over any window of release times, a bucket with rate R and burst B admits
        /// at most R times the window plus B + 1 requests. The extra one is the
        /// request that finds an empty bucket, as nginx admits it.
        #[test]
        fn the_bucket_never_admits_more_than_rate_times_time_plus_burst(
            interval_ms in 1_u64..=2000,
            burst in 0_u32..=5,
            undelayed_seed in 0_u32..=5,
            gaps in proptest::collection::vec(0_u64..=1500, 1..60),
        ) {
            let undelayed = undelayed_seed.min(burst);
            let interval_ns = interval_ms * 1_000_000;
            let zone = store(10_000, interval_ns);
            let limit = req(burst, undelayed);
            let base = Instant::now();
            let mut at = 0_u64;
            let mut releases: Vec<u128> = Vec::new();
            let mut held = Vec::new();
            for gap in gaps {
                at += gap;
                let now = base + Duration::from_millis(at);
                let Ok(admission) = zone.admit("k", &limit, false, now) else {
                    continue;
                };
                if admission.status == ReqStatus::Rejected {
                    continue;
                }
                releases.push(now.duration_since(base).as_nanos() + admission.wait.as_nanos());
                held.push(admission);
            }
            releases.sort_unstable();
            let interval = u128::from(interval_ns);
            for (i, start) in releases.iter().enumerate() {
                for (j, end) in releases.iter().enumerate().skip(i) {
                    let count = u128::try_from(j - i + 1).unwrap_or(u128::MAX);
                    let span = end - start;
                    // count <= span / interval + burst + 1, multiplied through by interval.
                    let allowed = span + (u128::from(burst) + 1) * interval;
                    prop_assert!(count * interval <= allowed, "count {count} span {span}");
                }
            }
        }
    }
}
