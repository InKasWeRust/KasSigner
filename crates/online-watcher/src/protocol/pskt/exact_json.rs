use serde_json::{Map, Number, Value};

const JS_MAX_SAFE_U64: u64 = 9_007_199_254_740_991;

pub(crate) fn parse_exact_u64(value: &Value, field: &str) -> Result<u64, String> {
    match value {
        Value::String(text) => parse_decimal_u64(text, field),
        Value::Number(number) => parse_legacy_safe_number(number, field),
        _ => Err(format!("{field} must be a decimal string")),
    }
}

pub(crate) fn canonicalize_pskt_exact_fields(pskt: &mut Value) -> Result<(), String> {
    let document = pskt
        .as_object_mut()
        .ok_or_else(|| "PSKT must be an object".to_string())?;
    canonicalize_global(document)?;
    canonicalize_inputs(document)?;
    canonicalize_outputs(document)
}

fn canonicalize_global(document: &mut Map<String, Value>) -> Result<(), String> {
    let Some(global) = document.get_mut("global").and_then(Value::as_object_mut) else {
        return Ok(());
    };
    canonicalize_optional_field(global, "fallbackLockTime")?;
    canonicalize_optional_field(global, "gas")
}

fn canonicalize_inputs(document: &mut Map<String, Value>) -> Result<(), String> {
    let Some(inputs) = document.get_mut("inputs").and_then(Value::as_array_mut) else {
        return Ok(());
    };
    for (index, input) in inputs.iter_mut().enumerate() {
        canonicalize_input(input, index)?;
    }
    Ok(())
}

fn canonicalize_input(input: &mut Value, index: usize) -> Result<(), String> {
    let object = input
        .as_object_mut()
        .ok_or_else(|| format!("input[{index}] must be an object"))?;
    canonicalize_optional_field(object, "sequence")?;
    canonicalize_optional_field(object, "minTime")?;
    if let Some(utxo) = object.get_mut("utxoEntry").and_then(Value::as_object_mut) {
        canonicalize_optional_field(utxo, "amount")?;
        canonicalize_optional_field(utxo, "blockDaaScore")?;
    }
    Ok(())
}

fn canonicalize_outputs(document: &mut Map<String, Value>) -> Result<(), String> {
    let Some(outputs) = document.get_mut("outputs").and_then(Value::as_array_mut) else {
        return Ok(());
    };
    for (index, output) in outputs.iter_mut().enumerate() {
        let object = output
            .as_object_mut()
            .ok_or_else(|| format!("output[{index}] must be an object"))?;
        canonicalize_required_field(object, "amount")?;
    }
    Ok(())
}

fn canonicalize_required_field(object: &mut Map<String, Value>, field: &str) -> Result<(), String> {
    let value = object
        .get(field)
        .ok_or_else(|| format!("missing {field}"))?;
    let parsed = parse_exact_u64(value, field)?;
    object.insert(field.to_string(), Value::String(parsed.to_string()));
    Ok(())
}

fn canonicalize_optional_field(object: &mut Map<String, Value>, field: &str) -> Result<(), String> {
    let Some(value) = object.get(field) else {
        return Ok(());
    };
    if value.is_null() {
        return Ok(());
    }
    let parsed = parse_exact_u64(value, field)?;
    object.insert(field.to_string(), Value::String(parsed.to_string()));
    Ok(())
}

fn parse_decimal_u64(text: &str, field: &str) -> Result<u64, String> {
    if text.is_empty()
        || !text.bytes().all(|byte| byte.is_ascii_digit())
        || (text.len() > 1 && text.as_bytes()[0] == b'0')
    {
        return Err(format!(
            "{field} must be a canonical unsigned decimal string"
        ));
    }
    text.parse::<u64>()
        .map_err(|error| format!("invalid {field}: {error}"))
}

fn parse_legacy_safe_number(number: &Number, field: &str) -> Result<u64, String> {
    let value = number
        .as_u64()
        .ok_or_else(|| format!("{field} must be an unsigned integer"))?;
    if value > JS_MAX_SAFE_U64 {
        return Err(format!(
            "legacy numeric {field} exceeds JavaScript's exact integer range; encode it as a decimal string"
        ));
    }
    Ok(value)
}
