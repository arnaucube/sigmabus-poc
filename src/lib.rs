#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
/// Proof of concept implementation of [Sigmabus](https://eprint.iacr.org/2023/1406) as described in section 3 of the paper, using Groth16's zkSNARK scheme.
pub mod circuits;
pub mod sigmabus;
pub mod transcript;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("SigmaProof verification failed")]
    SigmaFail,
    #[error("GenZK verification failed")]
    GenZKFail,
}
