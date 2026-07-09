//! Shared wire DTOs for the E2EE covered_seals lag admin surface
//! (Stream H', H'7).
//!
//! soland (the principal-server) is the producer of these shapes:
//!
//! - `GET  /_soland/admin/realms/{id}/mls/covered-seals` projects the covered-seals state for the
//!   `ck:cell:ck.component.covered_seals.v1:<realm_id>` cell alongside the current governance Seal
//!   frontier so the operator can compute lag.
//! - `POST /_soland/admin/realms/{id}/mls/covered-seals/advance` folds the governance Seal set into
//!   the group's covered_seals accumulator and returns the new lag count.
//!
//! sodmin consumes the same shapes; sharing them here keeps producer and
//! consumer from drifting (mirrors the `admin::seal` sharing pattern).

use serde::{Deserialize, Serialize};

/// Default warning threshold (in Seals). Above this, the admin page paints
/// the lag in red so the operator sees the urgency. Pure so it can be
/// changed without re-pulling everything.
pub const DEFAULT_LAG_WARN_THRESHOLD: u64 = 5;

/// Snapshot returned by the covered-seals admin describe endpoint.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct CoveredSealsSnapshot {
    pub realm_id: String,
    /// Current MLS group epoch — a monotonically-increasing integer that
    /// the group bumps on every Add/Remove/Update.
    #[serde(default)]
    pub mls_epoch: u64,
    /// Governance Seal ids the current MLS epoch should cover.
    #[serde(default)]
    pub governance_seals: Vec<String>,
    /// Governance Seal ids the MLS group has acknowledged.
    #[serde(default)]
    pub covered_seals: Vec<String>,
    /// Latest Seal id reflected in `governance_seals`.
    #[serde(default)]
    pub latest_seal_id: Option<String>,
    #[serde(default)]
    pub last_covered_at: Option<String>,
}

/// Response from the `POST /_soland/admin/realms/{id}/mls/covered-seals/advance`
/// route. soland reports the new lag count after the override Control Move
/// landed; the page uses this to render an immediate "now caught up"
/// confirmation toast without waiting for a re-fetch round-trip.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct CoveredSealsAdvanceOutcome {
    pub realm_id: String,
    /// New lag count after the override landed. Typically 0; non-zero
    /// means new governance Seals landed concurrently and the admin has
    /// to retry.
    #[serde(default)]
    pub lag_count: u64,
    /// Control Move id of the override commit.
    #[serde(default)]
    pub control_move_id: Option<String>,
}

impl CoveredSealsSnapshot {
    /// Lag = number of governance Seals the MLS group has not yet
    /// acknowledged. Computed as set-difference (governance \ covered);
    /// duplicates in either side are dropped before the diff so the count
    /// is canonical. Always returns `0` when MLS is fully caught up.
    pub fn lag_count(&self) -> u64 {
        let covered: std::collections::HashSet<&str> =
            self.covered_seals.iter().map(|s| s.as_str()).collect();
        let mut seen = std::collections::HashSet::new();
        let mut count: u64 = 0;
        for seal_id in &self.governance_seals {
            if covered.contains(seal_id.as_str()) {
                continue;
            }
            if seen.insert(seal_id.as_str()) {
                count += 1;
            }
        }
        count
    }

    /// True iff the lag is above the threshold passed in. Pure helper so
    /// the page can switch a Badge variant without re-doing the math.
    pub fn lag_above(&self, threshold: u64) -> bool {
        self.lag_count() > threshold
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lag_zero_when_covered_matches_governance() {
        let snap = CoveredSealsSnapshot {
            realm_id: "ak:realm:demo".into(),
            mls_epoch: 4,
            governance_seals: vec!["ak:seal:1".into(), "ak:seal:2".into(), "ak:seal:3".into()],
            covered_seals: vec!["ak:seal:3".into(), "ak:seal:1".into(), "ak:seal:2".into()],
            ..Default::default()
        };
        assert_eq!(snap.lag_count(), 0);
        assert!(!snap.lag_above(DEFAULT_LAG_WARN_THRESHOLD));
    }

    #[test]
    fn lag_counts_only_unacknowledged_moves() {
        let snap = CoveredSealsSnapshot {
            realm_id: "ak:realm:demo".into(),
            mls_epoch: 7,
            governance_seals: vec![
                "ak:seal:1".into(),
                "ak:seal:2".into(),
                "ak:seal:3".into(),
                "ak:seal:4".into(),
                "ak:seal:5".into(),
                "ak:seal:6".into(),
                "ak:seal:7".into(),
                "ak:seal:8".into(),
            ],
            covered_seals: vec!["ak:seal:1".into(), "ak:seal:2".into()],
            ..Default::default()
        };
        // 8 governance Seals - 2 covered Seals = 6 lag, above default threshold 5.
        assert_eq!(snap.lag_count(), 6);
        assert!(snap.lag_above(DEFAULT_LAG_WARN_THRESHOLD));
        assert!(!snap.lag_above(10));
    }

    #[test]
    fn lag_dedupes_duplicates_in_governance() {
        // soland normally canonicalizes the frontier, but if duplicates
        // ever leak through we must not double-count them.
        let snap = CoveredSealsSnapshot {
            governance_seals: vec!["ak:seal:1".into(), "ak:seal:1".into(), "ak:seal:2".into()],
            covered_seals: vec![],
            ..Default::default()
        };
        assert_eq!(snap.lag_count(), 2);
    }

    #[test]
    fn lag_threshold_boundary_is_strict_greater_than() {
        let snap = CoveredSealsSnapshot {
            governance_seals: vec!["ak:seal:1".into(), "ak:seal:2".into(), "ak:seal:3".into()],
            covered_seals: vec![],
            ..Default::default()
        };
        // lag == threshold should NOT trip the warning (strictly greater).
        assert_eq!(snap.lag_count(), 3);
        assert!(!snap.lag_above(3));
        assert!(snap.lag_above(2));
    }
}
