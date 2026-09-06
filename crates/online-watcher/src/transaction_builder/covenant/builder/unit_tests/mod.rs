use super::*;

#[test]
fn dust_policy_short_circuit_terms_are_independent() {
    assert_eq!(
        apply_dust_policy(CovenantDustPolicy::Preserve, 100, 101, 0, true),
        Ok(100),
    );
    assert_eq!(
        apply_dust_policy(CovenantDustPolicy::FoldSubKip9Change, 100, 101, 0, false),
        Ok(100),
    );
    assert_eq!(
        apply_dust_policy(CovenantDustPolicy::FoldSubKip9Change, 100, 101, 0, true),
        Ok(101),
    );

    let selected = 100_000_000;
    let fee = 10_000;
    let total = selected + fee + KIP9_MIN_CHANGE_SOMPI;
    assert_eq!(
        apply_dust_policy(
            CovenantDustPolicy::FoldSubKip9Change,
            selected,
            total,
            fee,
            true,
        ),
        Ok(selected),
        "change at the KIP-9 minimum is preserved rather than folded",
    );
}
