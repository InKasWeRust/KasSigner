pub fn push_data(script: &mut Vec<u8>, data: &[u8]) {
    let length = data.len();
    if length <= 75 {
        script.push(u8::try_from(length).expect("length is bounded by 75"));
    } else if length <= u8::MAX as usize {
        script.push(0x4c);
        script.push(u8::try_from(length).expect("length is bounded by u8::MAX"));
    } else if length <= u16::MAX as usize {
        script.push(0x4d);
        script.extend_from_slice(
            &u16::try_from(length)
                .expect("length is bounded by u16::MAX")
                .to_le_bytes(),
        );
    } else {
        script.push(0x4e);
        let length = u32::try_from(length).expect("script item exceeds u32 wire limit");
        script.extend_from_slice(&length.to_le_bytes());
    }
    script.extend_from_slice(data);
}

pub fn push_pubkey(script: &mut Vec<u8>, public_key: &[u8; 32]) {
    script.push(0x20);
    script.extend_from_slice(public_key);
}
