#![forbid(unsafe_code)]

pub mod rules;

use pfg_model::{FindingCategory, Severity};

#[derive(Debug, Clone, Default)]
pub struct PolicyEngine;

impl PolicyEngine {
    pub fn balanced() -> Self {
        Self
    }

    pub fn categorize_severity(&self, category: FindingCategory, key: &str) -> Severity {
        rules::categorize_severity(category, key)
    }
}
