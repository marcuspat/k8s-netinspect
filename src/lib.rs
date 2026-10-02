//! k8s-netinspect library
//!
//! Kubernetes network diagnostics. A [`snapshot::ClusterSnapshot`] is
//! collected (or loaded from disk), [`analysis::analyze`] turns it into a
//! [`model::Report`] of findings, and [`output`] renders it.

pub mod analysis;
pub mod commands;
pub mod errors;
pub mod model;
pub mod output;
pub mod probe;
pub mod rules;
pub mod snapshot;
pub mod validation;

// Re-export commonly used types for convenience
pub use errors::{NetInspectError, NetInspectResult};
pub use validation::Validator;
