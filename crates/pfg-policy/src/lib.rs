#![forbid(unsafe_code)]

pub mod profile;
pub mod rules;

pub use profile::CleanProfile;
use serde::{Deserialize, Serialize};
use pfg_model::{FindingCategory, Finding, Severity};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyAction {
    Remove,
    Preserve,
    Warn,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyEngine {
    pub profile: CleanProfile,
}

impl PolicyEngine {
    pub fn balanced() -> Self {
        Self {
            profile: CleanProfile::Balanced,
        }
    }

    pub fn strict() -> Self {
        Self {
            profile: CleanProfile::Strict,
        }
    }

    pub fn for_profile(profile: CleanProfile) -> Self {
        Self { profile }
    }

    pub fn categorize_severity(&self, category: FindingCategory, key: &str) -> Severity {
        rules::categorize_severity(category, key)
    }

    pub fn action_for(&self, finding: &Finding) -> PolicyAction {
        match self.profile {
            CleanProfile::Strict => PolicyAction::Remove,
            CleanProfile::Balanced => {
                match finding.category {
                    FindingCategory::Comments => {
                        if finding.key == "iCCP" || finding.key == "pHYs" || finding.key == "sPLT" || finding.key == "Annotation" || finding.key == "Annots" {
                            PolicyAction::Preserve
                        } else {
                            PolicyAction::Remove
                        }
                    }
                    FindingCategory::EmbeddedContent => PolicyAction::Preserve,
                    _ => PolicyAction::Remove,
                }
            }
        }
    }
}
