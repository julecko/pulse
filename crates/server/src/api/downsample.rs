//! Choosing a history bucket width when the client doesn't specify one.

/// "Nice" bucket widths in milliseconds: 1s, 5s, 10s, 30s, 1m, 5m, 15m, 30m,
/// 1h, 3h, 6h.
const STEPS_MS: [u64; 11] = [
    1_000, 5_000, 10_000, 30_000, 60_000, 300_000, 900_000, 1_800_000, 3_600_000, 10_800_000,
    21_600_000,
];

/// Smallest step that keeps the `[from_ms, to_ms)` span at roughly
/// `target_points` buckets or fewer. Never returns 0.
pub fn pick_bucket(from_ms: u64, to_ms: u64, target_points: u64) -> u64 {
    let span = to_ms.saturating_sub(from_ms).max(1);
    let ideal = span / target_points.max(1);
    STEPS_MS
        .iter()
        .copied()
        .find(|s| *s >= ideal)
        .unwrap_or(STEPS_MS[STEPS_MS.len() - 1])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn never_zero_and_bounded() {
        for &(from, to) in &[(0u64, 1u64), (0, 3_600_000), (0, 7 * 86_400_000), (5, 5)] {
            let b = pick_bucket(from, to, 500);
            assert!(b >= 1_000);
            let span = to.saturating_sub(from).max(1);
            assert!(span / b <= 1000, "span {span} / bucket {b} too many points");
        }
    }

    #[test]
    fn picks_expected_steps() {
        assert_eq!(pick_bucket(0, 3_600_000, 500), 10_000); // 1h -> 10s
        assert_eq!(pick_bucket(0, 7 * 86_400_000, 500), 1_800_000); // 7d -> 30m
    }
}
