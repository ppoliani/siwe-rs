use std::iter::FromIterator;
use alloy::{
  primitives::{Address, Bytes, FixedBytes}, providers::ProviderBuilder, rpc::client::RpcClient,
  sol, transports::http::reqwest::Url
};

use crate::VerificationError;

sol! {
  #[sol(rpc)] 
  contract ERC1271 { 
    function isValidSignature(
      bytes32 hash,
      bytes memory signature
    ) public view returns (bytes4);
  }
}

pub async fn verify_eip1271(
    address: [u8; 20],
    message_hash: &[u8; 32],
    signature: &[u8],
    rpc_url: &str
) -> Result<bool, VerificationError> {
    let rpc_url = Url::parse(rpc_url).unwrap();
    let rpc_client = RpcClient::new_http(rpc_url.into());
    let provider = ProviderBuilder::new().connect_client(rpc_client);
    let contract = ERC1271::new(Address::from_slice(&address), &provider);
    let is_valid_result = contract.isValidSignature(
        message_hash.into(),
        Bytes::from_iter(signature),
    ).call().await;

    match is_valid_result {
        Ok(FixedBytes([22, 38, 186, 126])) => Ok(true),
        Ok(FixedBytes([255, 255, 255, 255])) => Ok(false),
        Ok(_) => Err(VerificationError::Eip1271NonCompliant)?,
        Err(e) => Err(VerificationError::ContractCall(e.to_string())),
    }
}
