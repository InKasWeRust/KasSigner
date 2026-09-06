// KasSigner — GC0308 camera façade for M5Stack CoreS3.
// Sensor data, SCCB access, power sequencing, and initialization are isolated.
// ESP-HAL exclusively owns LCD_CAM clocks, GPIO matrix routing, IO_MUX and DVP pins.

mod bus;
mod initialization;
mod power;
mod registers;
mod types;

pub use initialization::{begin_entropy_capture, end_entropy_capture, init_gc0308};
pub use types::CameraStatus;
