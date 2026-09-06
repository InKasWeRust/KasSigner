//! Commit-reveal spend request validation and transaction planning.

use serde::Deserialize;

#[derive(Deserialize)]
struct CommitRevealSpendApiRequest {
    covenant_address: String,
    dest_address: String,
    redeem_script_hex: String,
    part_a_hex: String,
    part_b_hex: String,
    payload_hex: String,
    fee: String,
    ws_url: String,
}

pub(crate) struct CommitRevealSpendRequest {
    pub(crate) covenant_address: String,
    pub(crate) destination_address: String,
    pub(crate) redeem_script: Vec<u8>,
    pub(crate) part_a_hex: String,
    pub(crate) part_b_hex: String,
    pub(crate) payload: Vec<u8>,
    pub(crate) fee: u64,
    pub(crate) websocket_url: String,
}

pub(crate) fn parse(request_json: &str) -> Result<CommitRevealSpendRequest, String> {
    let request: CommitRevealSpendApiRequest =
        crate::serialization::input::parse_named_json(request_json, "commit-reveal spend request")?;
    Ok(CommitRevealSpendRequest {
        covenant_address: request.covenant_address,
        destination_address: request.dest_address,
        redeem_script: decode_hex(&request.redeem_script_hex, "redeem")?,
        part_a_hex: decode_and_preserve(&request.part_a_hex, "part_a")?,
        part_b_hex: decode_and_preserve(&request.part_b_hex, "part_b")?,
        payload: decode_hex(&request.payload_hex, "payload")?,
        fee: crate::serialization::input::parse_u64(&request.fee, "fee")?,
        websocket_url: request.ws_url,
    })
}

pub(crate) async fn build(request_json: &str) -> Result<String, String> {
    let request = parse(request_json)?;
    let (_, wire) = crate::transaction_builder::pskb::application::build_covenant_sweep(
        crate::transaction_builder::pskb::application::CovenantSweepRequest {
            websocket_url: &request.websocket_url,
            covenant_address: &request.covenant_address,
            destination_address: &request.destination_address,
            fee: request.fee,
            redeem_script: &request.redeem_script,
            branch: "beneficiary",
            proprietaries: serde_json::json!({
                "commitPartA": request.part_a_hex,
                "commitPartB": request.part_b_hex,
            }),
            signature_op_count: 1,
            transaction_payload: Some(request.payload),
            empty_error: "No UTXOs at covenant address",
            low_balance_error: "Balance too low to cover fee",
        },
    )
    .await?;
    Ok(wire)
}

fn decode_hex(value: &str, field: &str) -> Result<Vec<u8>, String> {
    hex::decode(value).map_err(|error| format!("Bad {field} hex: {error}"))
}

fn decode_and_preserve(value: &str, field: &str) -> Result<String, String> {
    decode_hex(value, field)?;
    Ok(value.to_string())
}
