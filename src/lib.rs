//! k8s-netinspect library
//! 
//! A comprehensive Kubernetes network debugging tool that provides
//! advanced RBAC validation and network connectivity analysis.

pub mod errors;
pub mod validation;
pub mod commands;

// Re-export commonly used types for convenience
pub use errors::{NetInspectError, NetInspectResult};
pub use validation::Validator;