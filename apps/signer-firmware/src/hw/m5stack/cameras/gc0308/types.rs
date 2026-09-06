/// Camera initialization state.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CameraStatus {
    SensorReady,
    Streaming,
    Error,
}
