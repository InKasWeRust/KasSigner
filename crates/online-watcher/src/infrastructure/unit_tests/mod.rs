#[cfg(not(target_arch = "wasm32"))]
#[test]
fn browser_log_is_a_safe_noop_on_native_targets() {
    let result = std::panic::catch_unwind(|| {
        super::browser_log::info("native coverage logging");
        super::browser_log::info(String::from("owned native coverage logging"));
    });
    assert!(result.is_ok());
}

#[test]
fn browser_response_validation_covers_identity_operation_success_and_remote_errors() {
    use crate::network::{error::NetworkError, wrpc::operation::Operation};

    fn response(id: Option<u64>, kind: u8, operation: Option<u8>, payload: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        match id {
            Some(value) => {
                bytes.push(1);
                bytes.extend_from_slice(&value.to_le_bytes());
            }
            None => bytes.push(0),
        }
        bytes.push(kind);
        match operation {
            Some(value) => bytes.extend_from_slice(&[1, value]),
            None => bytes.push(0),
        }
        bytes.extend_from_slice(payload);
        bytes
    }

    let operation = Operation::GetBlock;
    let success = response(Some(7), 0, Some(operation.code()), &[0xaa, 0xbb]);
    assert_eq!(
        super::browser_websocket::validate_response(&success, 7, operation).unwrap(),
        vec![0xaa, 0xbb],
    );

    let anonymous = response(None, 0, None, &[0xcc]);
    assert_eq!(
        super::browser_websocket::validate_response(&anonymous, 99, operation).unwrap(),
        vec![0xcc],
    );

    let wrong_id = response(Some(8), 0, Some(operation.code()), &[]);
    assert!(matches!(
        super::browser_websocket::validate_response(&wrong_id, 7, operation),
        Err(NetworkError::MismatchedRequestId {
            expected: 7,
            actual: 8
        })
    ));

    let wrong_operation = response(Some(7), 0, Some(Operation::GetUtxosByAddresses.code()), &[]);
    assert!(matches!(
        super::browser_websocket::validate_response(&wrong_operation, 7, operation),
        Err(NetworkError::MismatchedOperation { .. })
    ));

    let unknown_operation = response(Some(7), 0, Some(0xff), &[]);
    assert!(matches!(
        super::browser_websocket::validate_response(&unknown_operation, 7, operation),
        Err(NetworkError::MismatchedOperation { actual: 0xff, .. })
    ));

    let remote = response(Some(7), 2, Some(operation.code()), b"node rejected request");
    assert!(matches!(
        super::browser_websocket::validate_response(&remote, 7, operation),
        Err(NetworkError::RemoteError(message)) if message.contains("kind=2")
    ));

    assert!(super::browser_websocket::validate_response(&[2], 7, operation).is_err());
}

#[test]
fn browser_websocket_transport_constructor_validates_endpoint_without_browser_io() {
    use super::browser_websocket::BrowserWebSocketTransport;

    assert!(BrowserWebSocketTransport::new("ws://127.0.0.1:17110").is_ok());
    assert!(BrowserWebSocketTransport::new("  ").is_err());
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn browser_websocket_transport_call_is_deterministically_unavailable_on_native_hosts() {
    use super::browser_websocket::BrowserWebSocketTransport;
    use crate::{network::wrpc::operation::Operation, wasm_api::test_support::ready};

    let transport = BrowserWebSocketTransport::new("ws://127.0.0.1:17110").expect("transport");
    let error = ready(transport.call(Operation::GetBlock, &[1, 2, 3])).expect_err("native call");
    assert!(error.to_string().contains("unavailable on native hosts"));
}
