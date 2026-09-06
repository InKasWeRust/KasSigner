pub(crate) mod context;
pub(crate) mod plan;
pub(crate) mod request;

pub(crate) fn parse_request_json(request_json: &str) -> Result<request::PublishRequest, String> {
    let api: request::PublishApiRequest =
        crate::serialization::input::parse_named_json(request_json, "oracle publish request")?;
    let fee = crate::serialization::input::parse_u64(&api.fee, "fee")?;
    request::PublishRequest::parse_string(request::PublishRequestInput {
        wallet_json: &api.wallet_json,
        oracle_address: &api.oracle_address,
        redeem_script_hex: &api.redeem_script_hex,
        covenant_id_hex: &api.covenant_id_hex,
        heartbeat_cov_id_hex: &api.heartbeat_cov_id_hex,
        image_id_hex: &api.image_id_hex,
        control_id_hex: &api.control_id_hex,
        set_root_hex: &api.set_root_hex,
        hashfn_hex: &api.hashfn_hex,
        seal_hex: &api.seal_hex,
        claim_hex: &api.claim_hex,
        control_index_hex: &api.control_index_hex,
        control_digests_hex: &api.control_digests_hex,
        journal_hex: &api.journal_hex,
        fee,
        change_address: &api.change_address,
        network: &api.network,
        ws_url: &api.ws_url,
        omit_heartbeat: api.omit_heartbeat,
    })
}
