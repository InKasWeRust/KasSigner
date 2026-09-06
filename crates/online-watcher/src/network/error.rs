use std::fmt;

#[derive(Debug)]
pub enum NetworkError {
    InvalidUrl,
    ConnectionFailed(String),
    ConnectTimeout,
    ResponseTimeout,
    SendFailed,
    UnexpectedResponse(String),
    MismatchedRequestId { expected: u64, actual: u64 },
    MismatchedOperation { expected: u8, actual: u8 },
    RemoteError(String),
    TruncatedPayload,
    InvalidLength,
    InvalidEncoding(String),
}

impl NetworkError {
    fn static_message(&self) -> Option<&'static str> {
        match self {
            Self::InvalidUrl => Some("invalid WebSocket URL"),
            Self::ConnectTimeout => Some("WebSocket connect timeout (15s)"),
            Self::ResponseTimeout => Some("WebSocket RPC response timeout (15s)"),
            Self::SendFailed => Some("WebSocket send failed"),
            Self::TruncatedPayload => Some("truncated RPC payload"),
            Self::InvalidLength => Some("invalid RPC length"),
            _ => None,
        }
    }

    fn fmt_detail(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConnectionFailed(reason) => {
                write!(formatter, "WebSocket connection failed: {reason}")
            }
            Self::UnexpectedResponse(reason) => {
                write!(formatter, "unexpected RPC response: {reason}")
            }
            Self::MismatchedRequestId { expected, actual } => {
                write!(
                    formatter,
                    "RPC response id mismatch: expected {expected}, got {actual}"
                )
            }
            Self::MismatchedOperation { expected, actual } => {
                write!(
                    formatter,
                    "RPC operation mismatch: expected {expected}, got {actual}"
                )
            }
            Self::RemoteError(reason) => write!(formatter, "RPC error: {reason}"),
            Self::InvalidEncoding(reason) => write!(formatter, "invalid RPC encoding: {reason}"),
            _ => formatter.write_str("network error"),
        }
    }
}

impl fmt::Display for NetworkError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(message) = self.static_message() {
            formatter.write_str(message)
        } else {
            self.fmt_detail(formatter)
        }
    }
}

impl From<NetworkError> for String {
    fn from(error: NetworkError) -> Self {
        error.to_string()
    }
}
