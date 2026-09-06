use serde_json::{Map, Number, Value};

use crate::account::AddressBranch;

use crate::wire::pskt_envelope::{PSKB_MAGIC, PSKT_MAGIC};
const JS_MAX_SAFE_U64: u64 = 9_007_199_254_740_991;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Format {
    Pskb,
    Pskt,
}

pub(crate) fn decode(wire_hex: &str) -> Result<(Format, Value), String> {
    let wire = hex::decode(wire_hex).map_err(|error| format!("outer hex: {error}"))?;
    if wire.len() < 4 {
        return Err("payload too short".to_string());
    }
    let format = match wire.get(..4) {
        Some(value) if value == PSKB_MAGIC => Format::Pskb,
        Some(value) if value == PSKT_MAGIC => Format::Pskt,
        _ => return Err("Not a PSKT/PSKB payload".to_string()),
    };
    let inner = hex::decode(&wire[4..]).map_err(|error| format!("inner hex: {error}"))?;
    let root = serde_json::from_slice(&inner).map_err(|error| format!("JSON parse: {error}"))?;
    Ok((format, root))
}

pub(crate) fn encode(format: Format, root: &Value) -> Result<String, String> {
    let json = serde_json::to_vec(root).map_err(|error| format!("JSON encode: {error}"))?;
    let body = hex::encode(json);
    let magic = match format {
        Format::Pskb => PSKB_MAGIC,
        Format::Pskt => PSKT_MAGIC,
    };
    let mut wire = Vec::with_capacity(4 + body.len());
    wire.extend_from_slice(magic);
    wire.extend_from_slice(body.as_bytes());
    Ok(hex::encode(wire))
}

pub(crate) fn document(root: &Value, format: Format) -> Result<&Value, String> {
    match format {
        Format::Pskt => Ok(root),
        Format::Pskb => {
            let entries = root
                .as_array()
                .ok_or_else(|| "PSKB not array".to_string())?;
            if entries.len() != 1 {
                return Err(format!("PSKB must have 1 entry, got {}", entries.len()));
            }
            Ok(&entries[0])
        }
    }
}

pub(crate) fn document_mut(root: &mut Value, format: Format) -> Result<&mut Value, String> {
    match format {
        Format::Pskt => Ok(root),
        Format::Pskb => {
            let entries = root
                .as_array_mut()
                .ok_or_else(|| "PSKB not array".to_string())?;
            if entries.len() != 1 {
                return Err(format!("PSKB must have 1 entry, got {}", entries.len()));
            }
            Ok(&mut entries[0])
        }
    }
}

pub(crate) fn parse_exact_u64(value: &Value, field: &str) -> Result<u64, String> {
    match value {
        Value::String(text) => parse_decimal(text, field),
        Value::Number(number) => parse_legacy_number(number, field),
        _ => Err(format!("{field} must be a decimal string")),
    }
}

fn parse_decimal(text: &str, field: &str) -> Result<u64, String> {
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

fn parse_legacy_number(number: &Number, field: &str) -> Result<u64, String> {
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

pub(crate) fn parse_spk(value: &str) -> Result<(u16, Vec<u8>), String> {
    if value.len() < 4 {
        return Err(format!("scriptPublicKey too short: {}", value.len()));
    }
    let version = u16::from_str_radix(&value[..4], 16)
        .map_err(|error| format!("bad script version: {error}"))?;
    let script = hex::decode(&value[4..]).map_err(|error| format!("bad script hex: {error}"))?;
    Ok((version, script))
}

pub fn attach_input_derivation(
    pskt_hex: &str,
    input_index: usize,
    branch: AddressBranch,
    index: u32,
) -> Result<String, String> {
    attach_derivation(pskt_hex, "inputs", input_index, branch, index)
}

pub fn attach_output_derivation(
    pskt_hex: &str,
    output_index: usize,
    branch: AddressBranch,
    index: u32,
) -> Result<String, String> {
    attach_derivation(pskt_hex, "outputs", output_index, branch, index)
}

fn attach_derivation(
    pskt_hex: &str,
    section: &str,
    position: usize,
    branch: AddressBranch,
    index: u32,
) -> Result<String, String> {
    if index >= shared_signer::pairing::SOFT_INDEX_LIMIT {
        return Err("KasSigner derivation index must be non-hardened".to_string());
    }
    let (format, mut root) = decode(pskt_hex)?;
    let doc = document_mut(&mut root, format)?
        .as_object_mut()
        .ok_or_else(|| "PSKT not object".to_string())?;
    let entries = doc
        .get_mut(section)
        .and_then(Value::as_array_mut)
        .ok_or_else(|| format!("missing {section}"))?;
    let entry = entries
        .get_mut(position)
        .and_then(Value::as_object_mut)
        .ok_or_else(|| format!("{section}[{position}] not object"))?;
    let proprietaries = object_field_mut(entry, "proprietaries")?;
    let mut hint = Map::new();
    hint.insert("branch".to_string(), Value::from(branch.code()));
    hint.insert("index".to_string(), Value::String(index.to_string()));
    proprietaries.insert("kassignerDerivation".to_string(), Value::Object(hint));
    encode(format, &root)
}

fn object_field_mut<'a>(
    object: &'a mut Map<String, Value>,
    key: &str,
) -> Result<&'a mut Map<String, Value>, String> {
    if !matches!(object.get(key), Some(Value::Object(_))) {
        object.insert(key.to_string(), Value::Object(Map::new()));
    }
    object
        .get_mut(key)
        .and_then(Value::as_object_mut)
        .ok_or_else(|| format!("{key} must be an object"))
}

pub(crate) fn parse_derivation(value: &Value) -> Option<(u8, u32)> {
    value
        .get("kassignerDerivation")
        .and_then(Value::as_object)
        .and_then(|hint| {
            let branch = hint.get("branch").and_then(parse_derivation_branch);
            let index = hint
                .get("index")
                .and_then(parse_derivation_index)
                .filter(|index| *index < shared_signer::pairing::SOFT_INDEX_LIMIT);
            branch.zip(index)
        })
}

fn parse_derivation_branch(value: &Value) -> Option<u8> {
    value
        .as_u64()
        .and_then(|number| u8::try_from(number).ok())
        .filter(|branch| *branch <= 1)
}

fn parse_derivation_index(value: &Value) -> Option<u32> {
    value
        .as_str()
        .and_then(|text| text.parse::<u32>().ok())
        .or_else(|| value.as_u64().and_then(|number| u32::try_from(number).ok()))
}
