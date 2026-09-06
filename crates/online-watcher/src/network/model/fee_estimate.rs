use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct FeeEstimate {
    pub priority_sompi_per_gram: f64,
    pub normal_sompi_per_gram: f64,
    pub low_sompi_per_gram: f64,
    pub priority_seconds: f64,
    pub normal_seconds: f64,
    pub low_seconds: f64,
    #[serde(with = "crate::serialization::decimal_u64")]
    pub suggested_fee: u64,
}

impl FeeEstimate {
    pub fn conservative_fallback() -> Self {
        Self {
            priority_sompi_per_gram: 1.0,
            normal_sompi_per_gram: 1.0,
            low_sompi_per_gram: 1.0,
            priority_seconds: 1.0,
            normal_seconds: 30.0,
            low_seconds: 1800.0,
            suggested_fee: 10_000,
        }
    }
}
