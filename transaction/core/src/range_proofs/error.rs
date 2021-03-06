// Copyright (c) 2018-2020 MobileCoin Inc.

use displaydoc::Display;

#[derive(Debug, Display, PartialEq)]
pub enum Error {
    /// ProofError: `{0:?}`
    ProofError(bulletproofs::ProofError),

    /// Resize error
    ResizeError,
}

impl From<bulletproofs::ProofError> for Error {
    fn from(e: bulletproofs::ProofError) -> Self {
        Error::ProofError(e)
    }
}
