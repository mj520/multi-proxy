//! Load balancing strategies for upstream selection.

use sha2::{Sha256, Digest};

/// Load balancing strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Strategy {
    /// Order-based fallback: sequential selection by configured priority.
    Order,
    /// Hash-based session affinity: same target always starts at the same channel.
    Hash,
}

impl Strategy {
    /// Starting channel index for the given target.
    ///
    /// `Order` always starts at index 0 (highest priority first).
    /// `Hash` derives a stable index from the target so the same destination
    /// consistently maps to the same channel (session affinity); on failure
    /// the remaining channels are tried in order after rotating from here.
    pub(crate) fn start_index(&self, total: usize, target: &str) -> usize {
        match self {
            Strategy::Order => 0,
            Strategy::Hash => Self::hash_index(total, target),
        }
    }

    /// Stable hash → channel index in `[0, total)`.
    fn hash_index(total: usize, target: &str) -> usize {
        if total == 0 {
            return 0;
        }
        let mut hasher = Sha256::new();
        hasher.update(target.as_bytes());
        let result = hasher.finalize();
        // Use first 8 bytes as u64, then mod
        let hash = u64::from_le_bytes(result[..8].try_into().unwrap());
        (hash % total as u64) as usize
    }
}

impl From<crate::config::ConfigStrategy> for Strategy {
    fn from(c: crate::config::ConfigStrategy) -> Self {
        match c {
            crate::config::ConfigStrategy::Order => Strategy::Order,
            crate::config::ConfigStrategy::Hash => Strategy::Hash,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_consistency() {
        let idx1 = Strategy::Hash.start_index(5, "https://github.com");
        let idx2 = Strategy::Hash.start_index(5, "https://github.com");
        assert_eq!(idx1, idx2);
    }

    #[test]
    fn test_hash_distribution() {
        let indices: Vec<usize> = (0..100)
            .map(|i| Strategy::Hash.start_index(5, &format!("https://example.com/{}", i)))
            .collect();

        // Check distribution is reasonable (not all same)
        let unique: std::collections::HashSet<_> = indices.iter().collect();
        assert!(unique.len() > 1);
    }

    #[test]
    fn test_order_starts_at_zero() {
        assert_eq!(Strategy::Order.start_index(5, "test"), 0);
        assert_eq!(Strategy::Order.start_index(5, "anything"), 0);
    }

    #[test]
    fn test_hash_in_range() {
        for i in 0..200 {
            let target = format!("https://example.com/{}", i);
            let idx = Strategy::Hash.start_index(7, &target);
            assert!(idx < 7);
        }
    }
}
