use super::amounts::is_dust;

pub fn calculate_change(selected_total: u64, spend_total: u64, fee: u64) -> Result<u64, String> {
    let required = spend_total
        .checked_add(fee)
        .ok_or_else(|| "Spend plus fee exceeds supported monetary range".to_string())?;
    let change = selected_total.checked_sub(required).ok_or_else(|| {
        format!(
            "Selected UTXOs: {} sompi, need {} sompi",
            selected_total, required
        )
    })?;
    Ok(if is_dust(change) { 0 } else { change })
}
