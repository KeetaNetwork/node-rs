//! # Keetanetwork Node
//!
//! This crate provides node functionality for the Keetanetwork blockchain,
//! including the inbound peer-to-peer accept server built on the
//! [`keetanetwork_p2p`] switch.

pub mod log;
pub mod server;

pub use log::init as init_logging;
pub use server::{bind, serve, ServerError};
