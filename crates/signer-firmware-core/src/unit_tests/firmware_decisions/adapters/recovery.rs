use std::cell::RefCell;

use crate::input::recovery::run_i2c_recovery;

#[test]
fn i2c_recovery_pulses_clock_then_emits_stop() {
    let events = RefCell::new(std::vec::Vec::new());
    run_i2c_recovery(
        2,
        |high| events.borrow_mut().push(("clock", high)),
        |high| events.borrow_mut().push(("data", high)),
        || events.borrow_mut().push(("delay", false)),
    );
    assert_eq!(
        events.into_inner(),
        [
            ("data", true),
            ("clock", false),
            ("delay", false),
            ("clock", true),
            ("delay", false),
            ("clock", false),
            ("delay", false),
            ("clock", true),
            ("delay", false),
            ("data", false),
            ("delay", false),
            ("data", true),
            ("delay", false),
        ],
    );
}
