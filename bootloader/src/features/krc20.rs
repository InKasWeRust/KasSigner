// features/krc20.rs — KRC-20 token format detection

// KasSigner — KRC-20 Token Detection
// 100% Rust, no-std, no-alloc
//
// Detects KRC-20 (Kasplex) token operations in transaction scripts.
// KRC-20 uses a commit-reveal scheme:
//   Commit: P2SH with redeem script containing the Kasplex envelope
//   Reveal: spends the P2SH output, exposing the envelope on-chain
//
// The envelope format in the redeem script:
//   <pubkey> OP_CHECKSIG OP_FALSE OP_IF
//     OP_PUSH "kasplex"
//     OP_PUSH <content_type>
//     OP_PUSH <data>
//   OP_ENDIF
//
// The data payload is JSON:
//   {"p":"krc-20","op":"transfer","tick":"NACHO","amt":"100000000","to":"kaspa:..."}
//   {"p":"krc-20","op":"mint","tick":"KASPY"}
//   {"p":"krc-20","op":"deploy","tick":"TEST","max":"21000000","lim":"1000"}
//
// For KasSigner TX review: we extract op, tick, and amt from the JSON
// to show the user what KRC-20 operation is being signed.

/// Maximum ticker length (KRC-20 allows 4-6 chars)
pub const MAX_TICKER: usize = 8;

/// Maximum amount string length
pub const MAX_AMOUNT: usize = 32;

/// KRC-20 operation types
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Krc20Op {
    Deploy,
    Mint,
    Transfer,
    Unknown,
}

/// Detected KRC-20 token info from a transaction
#[derive(Debug, Clone)]
pub struct Krc20Info {
    pub op: Krc20Op,
    pub ticker: [u8; MAX_TICKER],
    pub ticker_len: usize,
    pub amount: [u8; MAX_AMOUNT],
    pub amount_len: usize,
    pub detected: bool,
}

impl Krc20Info {
        /// Create an empty KRC-20 detection result.
pub const fn empty() -> Self {
        Self {
            op: Krc20Op::Unknown,
            ticker: [0u8; MAX_TICKER],
            ticker_len: 0,
            amount: [0u8; MAX_AMOUNT],
            amount_len: 0,
            detected: false,
        }
    }

        /// Get the token ticker symbol.
pub fn ticker_str(&self) -> &str {
        core::str::from_utf8(&self.ticker[..self.ticker_len]).unwrap_or("????")
    }

        /// Get the formatted token amount.
pub fn amount_str(&self) -> &str {
        core::str::from_utf8(&self.amount[..self.amount_len]).unwrap_or("")
    }

        /// Get the operation type string (transfer, mint, etc.).
pub fn op_str(&self) -> &str {
        match self.op {
            Krc20Op::Deploy => "DEPLOY",
            Krc20Op::Mint => "MINT",
            Krc20Op::Transfer => "TRANSFER",
            Krc20Op::Unknown => "?",
        }
    }
}

/// Search for a JSON string value by key in raw bytes.
/// Looks for `"key":"value"` or `"key": "value"` pattern.
/// Returns (start, end) offsets of the value string content (excluding quotes).
fn find_json_string(data: &[u8], len: usize, key: &[u8]) -> Option<(usize, usize)> {
    // Search for "key" pattern
    let key_pattern_len = key.len() + 2; // "key"
    let mut i = 0;
    while i + key_pattern_len < len {
        if data[i] == b'"' && data[i + 1 + key.len()] == b'"' {
            if &data[i + 1..i + 1 + key.len()] == key {
                // Found key — now find the colon and value
                let mut j = i + key_pattern_len;
                // Skip whitespace and colon
                while j < len && (data[j] == b' ' || data[j] == b':') { j += 1; }
                // Expect opening quote
                if j < len && data[j] == b'"' {
                    let val_start = j + 1;
                    let mut val_end = val_start;
                    while val_end < len && data[val_end] != b'"' { val_end += 1; }
                    if val_end < len {
                        return Some((val_start, val_end));
                    }
                }
            }
        }
        i += 1;
    }
    None
}

/// Detect KRC-20 operation from a transaction's script payload.
/// Scans all input scripts and the transaction payload for Kasplex JSON data.
///
/// The JSON may appear in:
///   - Transaction payload field (if enabled in Kaspa protocol)
///   - Input script data (reveal transaction's redeem script)
///   - Output script (P2SH commit)
///
/// We search for the pattern `"p":"krc-20"` in any accessible data.
pub fn detect_krc20(tx: &crate::wallet::transaction::Transaction) -> Krc20Info {
    let mut info = Krc20Info::empty();

    // Check transaction payload
    if tx.payload_len > 0 {
        if try_parse_krc20(&tx.payload[..tx.payload_len], &mut info) {
            return info;
        }
    }

    // Check input scripts (reveal transaction carries data in script)
    for i in 0..tx.num_inputs {
        let script = &tx.inputs[i].utxo_entry.script_public_key;
        if script.script_len > 10 {
            if try_parse_krc20(&script.script[..script.script_len], &mut info) {
                return info;
            }
        }
    }

    // Check output scripts
    for i in 0..tx.num_outputs {
        let script = &tx.outputs[i].script_public_key;
        if script.script_len > 10 {
            if try_parse_krc20(&script.script[..script.script_len], &mut info) {
                return info;
            }
        }
    }

    info
}

/// Try to parse KRC-20 JSON from a byte buffer.
/// Returns true if valid KRC-20 data was found.
fn try_parse_krc20(data: &[u8], info: &mut Krc20Info) -> bool {
    let len = data.len();

    // Quick check: must contain "krc-20" or "KRC-20"
    let has_krc20 = contains_substr_ci(data, len, b"krc-20");
    if !has_krc20 { return false; }

    // Extract operation
    if let Some((start, end)) = find_json_string(data, len, b"op") {
        let op_len = end - start;
        let op_bytes = &data[start..end];
        info.op = if eq_ci(op_bytes, op_len, b"deploy") {
            Krc20Op::Deploy
        } else if eq_ci(op_bytes, op_len, b"mint") {
            Krc20Op::Mint
        } else if eq_ci(op_bytes, op_len, b"transfer") {
            Krc20Op::Transfer
        } else {
            Krc20Op::Unknown
        };
    }

    // Extract ticker
    if let Some((start, end)) = find_json_string(data, len, b"tick") {
        let tick_len = (end - start).min(MAX_TICKER);
        info.ticker[..tick_len].copy_from_slice(&data[start..start + tick_len]);
        info.ticker_len = tick_len;
    }

    // Extract amount (for transfer)
    if let Some((start, end)) = find_json_string(data, len, b"amt") {
        let amt_len = (end - start).min(MAX_AMOUNT);
        info.amount[..amt_len].copy_from_slice(&data[start..start + amt_len]);
        info.amount_len = amt_len;
    }

    info.detected = info.ticker_len > 0;
    info.detected
}

/// Case-insensitive substring search
fn contains_substr_ci(data: &[u8], len: usize, needle: &[u8]) -> bool {
    if needle.len() > len { return false; }
    for i in 0..=len - needle.len() {
        let mut matched = true;
        for j in 0..needle.len() {
            let a = data[i + j].to_ascii_lowercase();
            let b = needle[j].to_ascii_lowercase();
            if a != b { matched = false; break; }
        }
        if matched { return true; }
    }
    false
}

/// Case-insensitive equality
fn eq_ci(a: &[u8], a_len: usize, b: &[u8]) -> bool {
    if a_len != b.len() { return false; }
    for i in 0..a_len {
        if a[i].to_ascii_lowercase() != b[i].to_ascii_lowercase() { return false; }
    }
    true
}
