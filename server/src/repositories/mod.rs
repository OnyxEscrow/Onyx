//! Repository Layer
//!
//! Data access layer with business logic separation.
//! Repositories handle all database interactions with proper error handling,
//! encryption, and transaction management.

pub mod multisig_state;

pub use multisig_state::MultisigStateRepository;
