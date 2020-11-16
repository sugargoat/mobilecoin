// Copyright (c) 2018-2020 MobileCoin Inc.

//! JSON wrapper for the mobilecoind API.

pub mod data_types;

/// Connection to the mobilecoind client
pub struct State {
    pub mobilecoind_api_client: MobilecoindApiClient,
}

// mobilecoind-json API Version 2

use data_types::*;
use displaydoc::Display;
use mc_mobilecoind_api::mobilecoind_api_grpc::MobilecoindApiClient;
use rocket_contrib::json::Json;

#[derive(Display)]
pub enum APIError {
    /// Hex decode error
    HexDecode,

    /// u64 Parse Error
    ParseU64,

    /// Error with MobileCoind {0}
    MobilecoindError(grpcio::Error),
}

impl From<std::num::ParseIntError> for APIError {
    fn from(_e: std::num::ParseIntError) -> Self {
        Self::ParseU64
    }
}

impl From<hex::FromHexError> for APIError {
    fn from(_e: hex::FromHexError) -> Self {
        Self::ParseU64
    }
}

impl From<grpcio::Error> for APIError {
    fn from(e: grpcio::Error) -> Self {
        Self::MobilecoindError(e)
    }
}

// pub fn create_account(
//     params: JsonValue,
//     state: rocket::State<State>,
// ) -> Result<JsonValue, APIError> {
//     let mut req = mc_mobilecoind_api::CreateAccountRequest::new();
//     req.comment = params["comment"].to_string();
//
//     let resp = state.mobilecoind_api_client.create_account(&req)?;
//     Ok(json!(protobuf::text_format::print_to_string(&resp)).into())
// }
//
// pub fn create_address(
//     params: JsonValue,
//     state: rocket::State<State>,
// ) -> Result<JsonValue, APIError> {
//     let mut req = mc_mobilecoind_api::CreateAddressRequest::new();
//     req.expiration = params["expiration"].to_string().parse::<u64>()?;
//     req.comment = params["comment"].to_string();
//     req.account_id = hex::decode(params["account_id"].to_string())?;
//     let resp = state.mobilecoind_api_client.create_address(&req)?;
//     // FIXME: why doesn't it find protobuf::json??
//     Ok(json!(protobuf::text_format::print_to_string(&resp)).into())
// }

pub fn create_account(
    params: &WalletCreateAccountParams,
    state: rocket::State<State>,
) -> Result<Json<WalletCreateAccountResponse>, APIError> {
    let mut req = mc_mobilecoind_api::CreateAccountRequest::new();
    req.comment = params.comment.clone();

    let resp = state.mobilecoind_api_client.create_account(&req)?;
    Ok(Json(WalletCreateAccountResponse::from(&resp)))
}

pub fn create_address(
    params: &WalletCreateAddressParams,
    state: rocket::State<State>,
) -> Result<Json<WalletCreateAddressResponse>, APIError> {
    let mut req = mc_mobilecoind_api::CreateAddressRequest::new();
    req.expiration = params.expiration.parse::<u64>()?;
    req.comment = params.comment.clone();
    req.account_id = hex::decode(params.account_id.clone())?;
    let resp = state.mobilecoind_api_client.create_address(&req)?;
    Ok(Json(WalletCreateAddressResponse::from(&resp)))
}
