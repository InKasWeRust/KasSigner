/// QR encoding failure.
#[derive(Debug, PartialEq)]
pub enum QrError {
    DataTooLong,
}
