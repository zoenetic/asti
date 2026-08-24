//! Output renderers: human-readable terminal output, machine JSON, and
//! SARIF 2.1.0.

pub mod human;
pub mod json;
pub mod sarif;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Human,
    Json,
    Sarif,
}

impl std::str::FromStr for Format {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "human" | "text" => Ok(Format::Human),
            "json" => Ok(Format::Json),
            "sarif" => Ok(Format::Sarif),
            other => Err(format!("unknown format `{other}` (human, json, sarif)")),
        }
    }
}
