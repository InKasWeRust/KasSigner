use crate::network::wrpc::{operation::Operation, response};

#[test]
fn response_retains_request_identity() {
    let mut bytes = vec![1];
    bytes.extend_from_slice(&42u64.to_le_bytes());
    bytes.extend_from_slice(&[0, 1, Operation::GetBlock.code(), 0xaa, 0xbb]);

    let decoded = response::decode(&bytes).expect("response should decode");
    assert_eq!(decoded.id, Some(42));
    assert_eq!(decoded.operation, Some(Operation::GetBlock));
    assert_eq!(decoded.raw_operation, Some(Operation::GetBlock.code()));
    assert_eq!(decoded.payload, [0xaa, 0xbb]);
}

#[test]
fn response_rejects_invalid_option_tags() {
    assert!(response::decode(&[2, 0, 0]).is_err());
}

#[test]
fn wrpc_error_payload_extracts_declared_text_and_falls_back_on_invalid_length() {
    use crate::network::wrpc::error_payload;

    assert_eq!(error_payload::decode(b"short"), "short");

    let mut exact = vec![0u8; 10];
    exact[6..10].copy_from_slice(&6u32.to_le_bytes());
    exact.extend_from_slice(b"denied");
    assert_eq!(error_payload::decode(&exact), "denied");

    let mut truncated = vec![0u8; 10];
    truncated[6..10].copy_from_slice(&100u32.to_le_bytes());
    truncated.extend_from_slice(b"short");
    assert_eq!(
        error_payload::decode(&truncated),
        String::from_utf8_lossy(&truncated).into_owned()
    );
}
