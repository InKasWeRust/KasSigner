#[cfg(target_arch = "wasm32")]
use std::{
    cell::{Cell, RefCell},
    rc::Rc,
};

#[cfg(target_arch = "wasm32")]
use wasm_bindgen::{closure::Closure, JsCast};
#[cfg(target_arch = "wasm32")]
use wasm_bindgen_futures::JsFuture;
#[cfg(target_arch = "wasm32")]
use web_sys::{CloseEvent, Event, MessageEvent, WebSocket};

#[cfg(target_arch = "wasm32")]
use crate::network::wrpc::request::{self, WrpcRequest};
#[cfg(any(target_arch = "wasm32", test))]
use crate::network::wrpc::{
    error_payload,
    response::{self, ResponseKind},
};
use crate::network::{error::NetworkError, wrpc::operation::Operation};

const DEFAULT_TIMEOUT_MS: i32 = 15_000;

#[cfg(target_arch = "wasm32")]
type CallResult = Result<Vec<u8>, NetworkError>;
#[cfg(target_arch = "wasm32")]
type SharedCallResult = Rc<RefCell<Option<CallResult>>>;
#[cfg(target_arch = "wasm32")]
type SharedHandler<T> = Rc<RefCell<Option<T>>>;
#[cfg(target_arch = "wasm32")]
type SharedTimeoutId = Rc<RefCell<Option<i32>>>;
#[cfg(target_arch = "wasm32")]
type OpenHandler = Closure<dyn FnMut(Event)>;
#[cfg(target_arch = "wasm32")]
type MessageHandler = Closure<dyn FnMut(MessageEvent)>;
#[cfg(target_arch = "wasm32")]
type ErrorHandler = Closure<dyn FnMut(Event)>;
#[cfg(target_arch = "wasm32")]
type CloseHandler = Closure<dyn FnMut(CloseEvent)>;
#[cfg(target_arch = "wasm32")]
type TimeoutHandler = Closure<dyn FnMut()>;

/// Browser WebSocket adapter. Domain codecs and transaction logic live elsewhere.
pub struct BrowserWebSocketTransport {
    endpoint: String,
    timeout_ms: i32,
}

impl BrowserWebSocketTransport {
    pub fn new(endpoint: &str) -> Result<Self, NetworkError> {
        if endpoint.trim().is_empty() {
            return Err(NetworkError::InvalidUrl);
        }
        Ok(Self {
            endpoint: endpoint.to_owned(),
            timeout_ms: DEFAULT_TIMEOUT_MS,
        })
    }

    #[cfg(target_arch = "wasm32")]
    pub async fn call(
        &self,
        operation: Operation,
        payload: &[u8],
    ) -> Result<Vec<u8>, NetworkError> {
        let websocket = WebSocket::new(&self.endpoint)
            .map_err(|error| NetworkError::ConnectionFailed(format!("{error:?}")))?;
        websocket.set_binary_type(web_sys::BinaryType::Arraybuffer);

        let request_id = (js_sys::Math::random() * 1_000_000.0) as u64;
        let request = request::encode(&WrpcRequest {
            id: request_id,
            operation,
            payload,
        })?;

        let result: SharedCallResult = Rc::new(RefCell::new(None));
        let open_handler: SharedHandler<OpenHandler> = Rc::new(RefCell::new(None));
        let message_handler: SharedHandler<MessageHandler> = Rc::new(RefCell::new(None));
        let error_handler: SharedHandler<ErrorHandler> = Rc::new(RefCell::new(None));
        let close_handler: SharedHandler<CloseHandler> = Rc::new(RefCell::new(None));
        let timeout_handler: SharedHandler<TimeoutHandler> = Rc::new(RefCell::new(None));
        let timeout_id: SharedTimeoutId = Rc::new(RefCell::new(None));
        let request_sent = Rc::new(Cell::new(false));

        let promise = js_sys::Promise::new(&mut {
            let websocket = websocket.clone();
            let result = Rc::clone(&result);
            let open_handler = Rc::clone(&open_handler);
            let message_handler = Rc::clone(&message_handler);
            let error_handler = Rc::clone(&error_handler);
            let close_handler = Rc::clone(&close_handler);
            let timeout_handler = Rc::clone(&timeout_handler);
            let timeout_id = Rc::clone(&timeout_id);
            let request_sent = Rc::clone(&request_sent);
            let timeout_ms = self.timeout_ms;

            move |resolve, _reject| {
                let on_open = Closure::wrap(Box::new({
                    let websocket = websocket.clone();
                    let request = request.clone();
                    let result = Rc::clone(&result);
                    let request_sent = Rc::clone(&request_sent);
                    let resolve = resolve.clone();
                    move |_: Event| {
                        let array = js_sys::Uint8Array::from(request.as_slice());
                        if websocket.send_with_array_buffer(&array.buffer()).is_err() {
                            complete(&result, &resolve, Err(NetworkError::SendFailed));
                        } else {
                            request_sent.set(true);
                        }
                    }
                }) as Box<dyn FnMut(Event)>);

                let on_message = Closure::wrap(Box::new({
                    let result = Rc::clone(&result);
                    let resolve = resolve.clone();
                    move |event: MessageEvent| {
                        let response_result = event
                            .data()
                            .dyn_into::<js_sys::ArrayBuffer>()
                            .map_err(|_| {
                                NetworkError::UnexpectedResponse("non-binary frame".into())
                            })
                            .and_then(|buffer| {
                                let array = js_sys::Uint8Array::new(&buffer);
                                let length = usize::try_from(array.length())
                                    .map_err(|_| NetworkError::InvalidLength)?;
                                let mut data = vec![0u8; length];
                                array.copy_to(&mut data);
                                validate_response(&data, request_id, operation)
                            });
                        complete(&result, &resolve, response_result);
                    }
                }) as Box<dyn FnMut(MessageEvent)>);

                let on_error = Closure::wrap(Box::new({
                    let result = Rc::clone(&result);
                    let resolve = resolve.clone();
                    move |_: Event| {
                        complete(
                            &result,
                            &resolve,
                            Err(NetworkError::ConnectionFailed("WebSocket error".into())),
                        );
                    }
                }) as Box<dyn FnMut(Event)>);

                let on_close = Closure::wrap(Box::new({
                    let result = Rc::clone(&result);
                    let resolve = resolve.clone();
                    move |event: CloseEvent| {
                        let reason = close_reason(&event);
                        complete(
                            &result,
                            &resolve,
                            Err(NetworkError::ConnectionFailed(reason)),
                        );
                    }
                }) as Box<dyn FnMut(CloseEvent)>);

                websocket.set_onopen(Some(on_open.as_ref().unchecked_ref()));
                websocket.set_onmessage(Some(on_message.as_ref().unchecked_ref()));
                websocket.set_onerror(Some(on_error.as_ref().unchecked_ref()));
                websocket.set_onclose(Some(on_close.as_ref().unchecked_ref()));
                *open_handler.borrow_mut() = Some(on_open);
                *message_handler.borrow_mut() = Some(on_message);
                *error_handler.borrow_mut() = Some(on_error);
                *close_handler.borrow_mut() = Some(on_close);

                if let Some(window) = web_sys::window() {
                    let on_timeout = Closure::wrap(Box::new({
                        let result = Rc::clone(&result);
                        let request_sent = Rc::clone(&request_sent);
                        let resolve = resolve.clone();
                        move || {
                            let error = if request_sent.get() {
                                NetworkError::ResponseTimeout
                            } else {
                                NetworkError::ConnectTimeout
                            };
                            complete(&result, &resolve, Err(error));
                        }
                    }) as Box<dyn FnMut()>);
                    if let Ok(id) = window.set_timeout_with_callback_and_timeout_and_arguments_0(
                        on_timeout.as_ref().unchecked_ref(),
                        timeout_ms,
                    ) {
                        *timeout_id.borrow_mut() = Some(id);
                        *timeout_handler.borrow_mut() = Some(on_timeout);
                    }
                }
            }
        });

        JsFuture::from(promise)
            .await
            .map_err(|_| NetworkError::UnexpectedResponse("promise rejected".into()))?;

        if let (Some(window), Some(id)) = (web_sys::window(), timeout_id.borrow_mut().take()) {
            window.clear_timeout_with_handle(id);
        }
        websocket.set_onopen(None);
        websocket.set_onmessage(None);
        websocket.set_onerror(None);
        websocket.set_onclose(None);
        let _ = websocket.close();
        drop(open_handler.borrow_mut().take());
        drop(message_handler.borrow_mut().take());
        drop(error_handler.borrow_mut().take());
        drop(close_handler.borrow_mut().take());
        drop(timeout_handler.borrow_mut().take());

        let outcome = result.borrow_mut().take();
        outcome.unwrap_or_else(|| Err(NetworkError::UnexpectedResponse("no response".into())))
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub async fn call(
        &self,
        operation: Operation,
        payload: &[u8],
    ) -> Result<Vec<u8>, NetworkError> {
        Err(NetworkError::ConnectionFailed(format!(
            "browser WebSocket transport is unavailable on native hosts \
             (endpoint={}, timeout_ms={}, operation={}, payload_bytes={})",
            self.endpoint,
            self.timeout_ms,
            operation.code(),
            payload.len(),
        )))
    }
}

#[cfg(target_arch = "wasm32")]
fn close_reason(event: &CloseEvent) -> String {
    let reason = event
        .reason()
        .chars()
        .filter(|character| !character.is_control())
        .take(160)
        .collect::<String>();
    format!(
        "closed before RPC response (code {}, clean={}, reason={reason})",
        event.code(),
        event.was_clean()
    )
}

#[cfg(target_arch = "wasm32")]
fn complete(result: &SharedCallResult, resolve: &js_sys::Function, value: CallResult) {
    let mut guard = result.borrow_mut();
    if guard.is_none() {
        *guard = Some(value);
        let _ = resolve.call0(&wasm_bindgen::JsValue::NULL);
    }
}

#[cfg(any(target_arch = "wasm32", test))]
pub(super) fn validate_response(
    bytes: &[u8],
    expected_id: u64,
    expected_operation: Operation,
) -> Result<Vec<u8>, NetworkError> {
    let response = response::decode(bytes)?;
    if let Some(actual) = response.id {
        if actual != expected_id {
            return Err(NetworkError::MismatchedRequestId {
                expected: expected_id,
                actual,
            });
        }
    }
    if let Some(actual) = response.raw_operation {
        if response.operation != Some(expected_operation) {
            return Err(NetworkError::MismatchedOperation {
                expected: expected_operation.code(),
                actual,
            });
        }
    }

    match response.kind {
        ResponseKind::Success => Ok(response.payload.to_vec()),
        ResponseKind::Error(code) => Err(NetworkError::RemoteError(format!(
            "kind={code}: {}",
            error_payload::decode(response.payload)
        ))),
    }
}
