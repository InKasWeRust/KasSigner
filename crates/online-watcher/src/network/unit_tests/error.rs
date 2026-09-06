use super::super::error::NetworkError;

#[test]
fn network_errors_have_stable_actionable_messages() {
    let cases = [
        (NetworkError::InvalidUrl, "invalid WebSocket URL"),
        (
            NetworkError::ConnectionFailed("refused".into()),
            "WebSocket connection failed: refused",
        ),
        (
            NetworkError::ConnectTimeout,
            "WebSocket connect timeout (15s)",
        ),
        (
            NetworkError::ResponseTimeout,
            "WebSocket RPC response timeout (15s)",
        ),
        (NetworkError::SendFailed, "WebSocket send failed"),
        (
            NetworkError::UnexpectedResponse("missing result".into()),
            "unexpected RPC response: missing result",
        ),
        (
            NetworkError::MismatchedRequestId {
                expected: 7,
                actual: 9,
            },
            "RPC response id mismatch: expected 7, got 9",
        ),
        (
            NetworkError::MismatchedOperation {
                expected: 2,
                actual: 3,
            },
            "RPC operation mismatch: expected 2, got 3",
        ),
        (
            NetworkError::RemoteError("denied".into()),
            "RPC error: denied",
        ),
        (NetworkError::TruncatedPayload, "truncated RPC payload"),
        (NetworkError::InvalidLength, "invalid RPC length"),
        (
            NetworkError::InvalidEncoding("bad varint".into()),
            "invalid RPC encoding: bad varint",
        ),
    ];

    for (error, expected) in cases {
        assert_eq!(error.to_string(), expected);
        let converted: String = error.into();
        assert_eq!(converted, expected);
    }
}
