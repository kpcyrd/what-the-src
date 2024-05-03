pub const STRAIN: &str = "cargo-lock";

#[derive(Debug, PartialEq)]
pub struct CargoLock {
    pub data: String,
}
