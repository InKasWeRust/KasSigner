use crate::camera::dma::{
    copy_sample_with, descriptor_action, plan_decode_submission, DescriptorAction,
};

#[test]
fn decode_submission_rejects_overflow_busy_and_buffer_mismatch() {
    assert_eq!(plan_decode_submission(4, 3, 12, true, true, 12), Some(12));
    assert_eq!(
        plan_decode_submission(usize::MAX, 2, 0, true, true, usize::MAX),
        None
    );
    assert_eq!(plan_decode_submission(4, 3, 11, true, true, 12), None);
    assert_eq!(plan_decode_submission(4, 3, 12, false, true, 12), None);
    assert_eq!(plan_decode_submission(4, 3, 12, true, false, 12), None);
    assert_eq!(plan_decode_submission(4, 3, 12, true, true, 11), None);
}

#[test]
fn sample_copy_and_descriptor_planning_are_bounds_safe() {
    let mut output = [0u8; 3];
    assert_eq!(
        copy_sample_with(&mut output, true, 2, |index| index as u8 + 7),
        2
    );
    assert_eq!(output, [7, 8, 0]);
    assert_eq!(copy_sample_with(&mut output, false, 3, |_| 1), 0);

    let control = 4u32 << 12;
    assert_eq!(descriptor_action(control, 2, 6), DescriptorAction::Copy(4));
    assert_eq!(
        descriptor_action(control | (1 << 31), 0, 4),
        DescriptorAction::Skip
    );
    assert_eq!(descriptor_action(control, 1, 4), DescriptorAction::Recycle);
    assert_eq!(descriptor_action(0, 0, 4), DescriptorAction::Recycle);
}
