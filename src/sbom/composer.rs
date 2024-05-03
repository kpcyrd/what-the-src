pub const STRAIN: &str = "composer-lock";

#[derive(Debug, PartialEq)]
pub struct ComposerLock {
    pub data: String,
}
