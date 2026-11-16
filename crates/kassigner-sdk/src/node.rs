// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! A node's wRPC for a spend ([`kassigner_kaspa::wrpc`], either encoding): the
//! coins an address holds, the fee rate, the signed transaction handed over.
//! [`request`] writes a call; [`read`] reads the answer.
//!
//! A signed transaction is [`Params::SubmitTransaction`] over the `transaction`
//! and `storage_mass` [`crate::reply::finalize`] returns, as
//! [`crate::reply::Finalized::submit_json`] writes it for the JSON port. The
//! connection, its ids and the node are the app's.

pub use kassigner_kaspa::wrpc::*;
