pub fn build_redeem_script(threshold: u8, public_keys: &[[u8; 32]]) -> Result<Vec<u8>, String> {
    let count =
        u8::try_from(public_keys.len()).map_err(|_| "Too many multisig public keys".to_string())?;
    if threshold == 0 || threshold > count || count > 16 {
        return Err(format!("Invalid {}-of-{} multisig", threshold, count));
    }

    let mut script = Vec::with_capacity(1 + public_keys.len() * 33 + 2);
    script.push(0x50 + threshold);
    for public_key in public_keys {
        script.push(0x20);
        script.extend_from_slice(public_key);
    }
    script.push(0x50 + count);
    script.push(0xae);
    Ok(script)
}
