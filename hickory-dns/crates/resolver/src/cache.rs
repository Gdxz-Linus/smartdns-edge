//! A cache for DNS responses.

use std::{
    collections::HashMap,
    ops::RangeInclusive,
    sync::Arc,
    time::{Duration, Instant},
};

use moka::{Expiry, sync::Cache};
#[cfg(feature = "serde")]
use serde::Deserialize;

use crate::config;
use crate::lookup::Lookup; // 🌟 引入 Lookup
use crate::proto::{
    NoRecords, ProtoError, ProtoErrorKind,
    op::Query,
    rr::RecordType,
};

/// A cache for DNS responses.
#[derive(Clone, Debug)]
pub struct ResponseCache {
    cache: Cache<Query, Entry>,
    ttl_config: Arc<TtlConfig>,
}

impl ResponseCache {
    /// Construct a new response cache.
    ///
    /// # Arguments
    ///
    /// * `capacity` - size in number of cached responses
    /// * `ttl_config` - minimum and maximum TTLs for cached records
    pub fn new(capacity: u64, ttl_config: TtlConfig) -> Self {
        Self {
            cache: Cache::builder()
                .max_capacity(capacity)
                .expire_after(EntryExpiry)
                .build(),
            ttl_config: Arc::new(ttl_config),
        }
    }

    /// Insert a response into the cache.
    pub fn insert(&self, query: Query, result: Result<Lookup, ProtoError>, now: Instant) {
        let ttl = match &result {
            Ok(lookup) => {
                let (positive_min_ttl, positive_max_ttl) = self
                    .ttl_config
                    .positive_response_ttl_bounds(query.query_type())
                    .into_inner();
                lookup
                    .records()
                    .iter()
                    .map(|record| Duration::from_secs(record.ttl().into()))
                    .min()
                    .unwrap_or(positive_min_ttl)
                    .clamp(positive_min_ttl, positive_max_ttl)
            }
            Err(e) => {
                let ProtoErrorKind::NoRecordsFound(no_records) = e.kind() else {
                    return;
                };
                let (negative_min_ttl, negative_max_ttl) = self
                    .ttl_config
                    .negative_response_ttl_bounds(query.query_type())
                    .into_inner();
                if let Some(ttl) = no_records.negative_ttl {
                    Duration::from_secs(u64::from(ttl)).clamp(negative_min_ttl, negative_max_ttl)
                } else {
                    negative_min_ttl
                }
            }
        };
        let valid_until = now + ttl;
        self.cache.insert(
            query,
            Entry {
                result: Arc::new(result),
                original_time: now,
                valid_until,
            },
        );
    }

    /// Try to retrieve a cached response with the given query.
    pub fn get(&self, query: &Query, now: Instant) -> Option<Result<Lookup, ProtoError>> {
        let entry = self.cache.get(query)?;
        if !entry.is_current(now) {
            return None;
        }
        Some(entry.updated_ttl(now))
    }

    pub(crate) fn clear(&self) {
        self.cache.invalidate_all();
    }
}

/// An entry in the response cache.
#[derive(Debug, Clone)]
struct Entry {
    result: Arc<Result<Lookup, ProtoError>>, // 🌟 改为直接缓存轻量级 Lookup
    original_time: Instant,
    valid_until: Instant,
}

impl Entry {
    /// Return the `Result` stored in this entry, with modified TTLs, subtracting the elapsed time
    /// since the response was received.
    fn updated_ttl(&self, now: Instant) -> Result<Lookup, ProtoError> {
        let elapsed = u32::try_from(now.saturating_duration_since(self.original_time).as_secs())
            .unwrap_or(u32::MAX);
        match &*self.result {
            Ok(lookup) => {
                let mut lookup = lookup.clone();
                // 🌟 极致优化：只拷贝并更新需要的 answers 记录，避免克隆整条 Message 极其多余的数据
                let mut records = lookup.records().to_vec();
                for record in &mut records {
                    record.set_ttl(record.ttl().saturating_sub(elapsed));
                }
                lookup.records = Arc::from(records);
                Ok(lookup)
            }
            Err(e) => {
                let mut e = e.clone();
                if let ProtoErrorKind::NoRecordsFound(NoRecords {
                    negative_ttl: Some(ttl),
                    ..
                }) = e.kind.as_mut()
                {
                    *ttl = ttl.saturating_sub(elapsed);
                }
                Err(e)
            }
        }
    }

    /// Returns whether this cache entry is still valid.
    fn is_current(&self, now: Instant) -> bool {
        now <= self.valid_until
    }

    /// Returns the remaining time that this cache entry is valid for.
    fn ttl(&self, now: Instant) -> Duration {
        self.max_ttl_on_create(now)
    }

    #[inline]
    fn max_ttl_on_create(&self, now: Instant) -> Duration {
        self.valid_until.saturating_duration_since(now)
    }
}

struct EntryExpiry;

impl Expiry<Query, Entry> for EntryExpiry {
    fn expire_after_create(
        &self,
        _key: &Query,
        value: &Entry,
        created_at: Instant,
    ) -> Option<Duration> {
        Some(value.ttl(created_at))
    }

    fn expire_after_update(
        &self,
        _key: &Query,
        value: &Entry,
        updated_at: Instant,
        _duration_until_expiry: Option<Duration>,
    ) -> Option<Duration> {
        Some(value.ttl(updated_at))
    }
}

/// The time-to-live (TTL) configuration used by the cache.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(from = "ttl_config_deserialize::TtlConfigMap")
)]
pub struct TtlConfig {
    default: TtlBounds,
    by_query_type: HashMap<RecordType, TtlBounds>,
}

impl TtlConfig {
    /// Construct the LRU's TTL configuration based on the ResolverOpts configuration.
    pub fn from_opts(opts: &config::ResolverOpts) -> Self {
        Self::from(TtlBounds {
            positive_min_ttl: opts.positive_min_ttl,
            negative_min_ttl: opts.negative_min_ttl,
            positive_max_ttl: opts.positive_max_ttl,
            negative_max_ttl: opts.negative_max_ttl,
        })
    }

    /// Override the minimum and maximum TTL values for a specific query type.
    pub fn with_query_type_ttl_bounds(
        &mut self,
        query_type: RecordType,
        bounds: TtlBounds,
    ) -> &mut Self {
        self.by_query_type.insert(query_type, bounds);
        self
    }

    /// Retrieves the minimum and maximum TTL values for positive responses.
    pub fn positive_response_ttl_bounds(&self, query_type: RecordType) -> RangeInclusive<Duration> {
        let bounds = self.by_query_type.get(&query_type).unwrap_or(&self.default);
        let min = bounds
            .positive_min_ttl
            .unwrap_or_else(|| Duration::from_secs(0));
        let max = bounds
            .positive_max_ttl
            .unwrap_or_else(|| Duration::from_secs(u64::from(MAX_TTL)));
        min..=max
    }

    /// Retrieves the minimum and maximum TTL values for negative responses.
    pub fn negative_response_ttl_bounds(&self, query_type: RecordType) -> RangeInclusive<Duration> {
        let bounds = self.by_query_type.get(&query_type).unwrap_or(&self.default);
        let min = bounds
            .negative_min_ttl
            .unwrap_or_else(|| Duration::from_secs(0));
        let max = bounds
            .negative_max_ttl
            .unwrap_or_else(|| Duration::from_secs(u64::from(MAX_TTL)));
        min..=max
    }
}

impl From<TtlBounds> for TtlConfig {
    fn from(default: TtlBounds) -> Self {
        Self {
            default,
            by_query_type: HashMap::default(),
        }
    }
}

/// Minimum and maximum TTL values for positive and negative responses.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Deserialize))]
#[cfg_attr(feature = "serde", serde(deny_unknown_fields))]
pub struct TtlBounds {
    #[cfg_attr(
        feature = "serde",
        serde(default, deserialize_with = "config::duration_opt::deserialize")
    )]
    positive_min_ttl: Option<Duration>,

    #[cfg_attr(
        feature = "serde",
        serde(default, deserialize_with = "config::duration_opt::deserialize")
    )]
    negative_min_ttl: Option<Duration>,

    #[cfg_attr(
        feature = "serde",
        serde(default, deserialize_with = "config::duration_opt::deserialize")
    )]
    positive_max_ttl: Option<Duration>,

    #[cfg_attr(
        feature = "serde",
        serde(default, deserialize_with = "config::duration_opt::deserialize")
    )]
    negative_max_ttl: Option<Duration>,
}

#[cfg(feature = "serde")]
mod ttl_config_deserialize {
    use std::collections::HashMap;

    use serde::Deserialize;

    use super::{TtlBounds, TtlConfig};
    use crate::proto::rr::RecordType;

    #[derive(Deserialize)]
    pub(super) struct TtlConfigMap(HashMap<TtlConfigField, TtlBounds>);

    impl From<TtlConfigMap> for TtlConfig {
        fn from(value: TtlConfigMap) -> Self {
            let mut default = TtlBounds::default();
            let mut by_query_type = HashMap::new();
            for (field, bounds) in value.0.into_iter() {
                match field {
                    TtlConfigField::RecordType(record_type) => {
                        by_query_type.insert(record_type, bounds);
                    }
                    TtlConfigField::Default => default = bounds,
                }
            }
            Self {
                default,
                by_query_type,
            }
        }
    }

    #[derive(PartialEq, Eq, Hash, Deserialize)]
    enum TtlConfigField {
        #[serde(rename = "default")]
        Default,
        #[serde(untagged)]
        RecordType(RecordType),
    }
}

/// Maximum TTL. This is set to one day (in seconds).
pub const MAX_TTL: u32 = 86400_u32;