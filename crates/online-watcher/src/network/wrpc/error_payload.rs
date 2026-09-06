pub fn decode(payload: &[u8]) -> String {
    if payload.len() > 10 {
        let encoded_length = u32::from_le_bytes([payload[6], payload[7], payload[8], payload[9]]);
        let Ok(length) = usize::try_from(encoded_length) else {
            return String::from_utf8_lossy(payload).into_owned();
        };
        let start = 10usize;
        if start
            .checked_add(length)
            .is_some_and(|end| end <= payload.len())
        {
            return String::from_utf8_lossy(&payload[start..start + length]).into_owned();
        }
    }
    String::from_utf8_lossy(payload).into_owned()
}
