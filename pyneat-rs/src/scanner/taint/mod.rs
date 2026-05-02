//! Taint Analysis Engine for PyNEAT.
//!
//! Provides data flow analysis to detect taint propagation from sources
//! (user input, network, files) to sinks (exec, SQL, eval).

pub mod labels;
pub mod dfg;
pub mod engine;
pub mod rules;
pub mod interproc;

#[cfg(test)]
mod tests;

