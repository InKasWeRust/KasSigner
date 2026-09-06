use super::*;

#[test]
fn owner_spec_distinguishes_time_branch_and_preserves_nonempty_branch() {
    let mut cltv = Vec::new();
    crate::protocol::script::push_int(&mut cltv, 500);
    cltv.push(0xb0);
    let timed = OwnerSpendPlan {
        redeem_script: cltv,
        branch: "owner-time".to_string(),
    };
    let (timed_spec, lock_time) = timed
        .spec("covenant", "destination", 1, "empty", "low")
        .expect("timed spec");
    assert_eq!(lock_time, 500);
    assert_eq!(timed_spec.config.lock_time, 500);
    assert_eq!(timed_spec.config.branch, Some("owner-time"));

    let plain = OwnerSpendPlan {
        redeem_script: vec![0x51],
        branch: "owner".to_string(),
    };
    let (plain_spec, lock_time) = plain
        .spec("covenant", "destination", 1, "empty", "low")
        .expect("plain spec");
    assert_eq!(lock_time, 0);
    assert_eq!(plain_spec.config.branch, Some("owner"));

    let empty = OwnerSpendPlan {
        redeem_script: vec![0x51],
        branch: String::new(),
    };
    let (empty_spec, _) = empty
        .spec("covenant", "destination", 1, "empty", "low")
        .expect("empty branch spec");
    assert_eq!(empty_spec.config.branch, None);
}
