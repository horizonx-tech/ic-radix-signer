use std::str::FromStr;

use ic_radix_signer::Hash;
use ic_radix_signer::ICSigner;
use ic_radix_signer::KeyInfo;
use ic_radix_signer::Signer;
#[ic_cdk::update]
async fn test_sign() -> String {
    let key_info = KeyInfo{
        derivation_path: vec![],
        ecdsa_sign_cycles: None,
        key_name: "dfx_test_key".to_string(),
    };
    let signer = ICSigner::new(key_info).await.unwrap();
    let msg_hash = Hash::from_str("b177968c9c68877dc8d33e25759183c556379daa45a4d78a2b91c70133c873ca").unwrap();
    let signature = signer.sign_with_public_key(&msg_hash);
    ic_cdk::println!("signature: {:?}", signature);
    "ok".to_string()
}
