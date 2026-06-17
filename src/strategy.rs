//! Load balancing strategies for upstream selection.

use sha2::{Sha256, Digest};

/// Load balancing strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Strategy {
    /// Order-based fallback: sequential selection.
    Order,
    /// Hash-based session affinity.
    Hash,
}

impl Strategy {
    /// Select index based on strategy.
    #[allow(dead_code)]
    pub fn select(&self, total: usize, target: &str, fallback_idx: usize) -> usize {
        match self {
            Strategy::Order => fallback_idx,
            Strategy::Hash => Self::hash_index(total, target),
        }
    }

    /// Calculate hash-based index for session affinity.
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
        let idx1 = Strategy::Hash.select(5, "https://github.com", 0);
        let idx2 = Strategy::Hash.select(5, "https://github.com", 0);
        assert_eq!(idx1, idx2);
    }

    #[test]
    fn test_hash_distribution() {
        let indices: Vec<usize> = (0..100)
            .map(|i| Strategy::Hash.select(5, &format!("https://example.com/{}", i), 0))
            .collect();

        // Check distribution is reasonable (not all same)
        let unique: std::collections::HashSet<_> = indices.iter().collect();
        assert!(unique.len() > 1);
    }

    #[test]
    fn test_order_always_fallback() {
        assert_eq!(Strategy::Order.select(5, "test", 2), 2);
        assert_eq!(Strategy::Order.select(5, "test", 0), 0);
    }
}