use std::str::FromStr;

use ic_radix_signer::signer::Signer;
use ic_radix_signer::Hash;
use ic_radix_signer::ICSigner;
use ic_radix_signer::KeyInfo;
use radix_common::address::AddressBech32Encoder;
use radix_common::address::AddressDisplayContext;
use radix_common::network::NetworkDefinition;
use radix_common::types::ComponentAddress;
use radix_common::prelude::ContextualDisplay;
#[ic_cdk::update]
async fn test_sign() -> String {
    let msg_hash = Hash::from_str("b177968c9c68877dc8d33e25759183c556379daa45a4d78a2b91c70133c873ca").unwrap();
    let signature = signer().await.unwrap().sign_with_public_key(msg_hash).await.unwrap();
    ic_cdk::println!("signature: {:?}", signature);
    "OK".to_string()
}

#[ic_cdk::update]
async fn account_address() -> String {
    let pub_key = signer().await.unwrap().public_key().await;
    let address = ComponentAddress::virtual_account_from_public_key(&pub_key);
    address.to_string(AddressDisplayContext::with_encoder(&AddressBech32Encoder::new(&NetworkDefinition::mainnet())))
}

async fn signer() -> Result<ICSigner, String> {
    let key_info = key_info();
    let signer = ICSigner::new(key_info).await.map_err(|e| e.to_string())?;
    Ok(signer)
}

fn key_info() -> KeyInfo {
    KeyInfo {
        derivation_path: vec![],
        ecdsa_sign_cycles: None,
        key_name: "dfx_test_key".to_string(),
    }
}
