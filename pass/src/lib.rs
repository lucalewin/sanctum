/*!
Library entry for the `pass` crate.

This file exposes the core types used by the examples and external callers:
- `Config` — application configuration (load/save).
- `Client` — primary client API for interacting with vaults/records.
- `Error` — crate-wide error type.

It also re-exports the internal modules so they remain available for integration tests or other consumers.
*/

pub mod client;
pub mod config;
pub mod crypto;
pub mod db;
pub mod models;
pub mod error;

pub use client::Client;
pub use config::Config;
pub use error::Error;
