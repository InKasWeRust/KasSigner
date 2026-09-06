use crate::power::sequencing::{run_register_writes, RegisterWriteStep};

#[test]
fn register_write_sequence_preserves_order_delays_and_address() {
    let steps = [
        RegisterWriteStep::new(1, 2, 0, "one"),
        RegisterWriteStep::new(3, 4, 7, "two"),
    ];
    let mut writes = std::vec::Vec::new();
    let mut delays = std::vec::Vec::new();
    assert_eq!(
        run_register_writes(
            0x34,
            &steps,
            |address, register, value| {
                writes.push((address, register, value));
                true
            },
            |milliseconds| delays.push(milliseconds),
        ),
        Ok(()),
    );
    assert_eq!(writes, [(0x34, 1, 2), (0x34, 3, 4)]);
    assert_eq!(delays, [7]);
}

#[test]
fn register_write_sequence_stops_at_the_first_failure() {
    let steps = [
        RegisterWriteStep::new(1, 2, 5, "first"),
        RegisterWriteStep::new(3, 4, 9, "second"),
    ];
    let mut writes = 0;
    let mut delays = std::vec::Vec::new();
    let result = run_register_writes(
        0x58,
        &steps,
        |_, _, _| {
            writes += 1;
            writes != 2
        },
        |milliseconds| delays.push(milliseconds),
    );
    assert_eq!(result, Err("second"));
    assert_eq!(writes, 2);
    assert_eq!(delays, [5]);
}
