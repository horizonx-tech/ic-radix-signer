use std::{cell::RefCell, collections::HashMap};

use anyhow::Result;
use ic_web3_rs::ic::{get_public_key, ic_raw_sign, KeyInfo};
use transaction::{
    prelude::{IsHash, PublicKey, Secp256k1PublicKey, Secp256k1Signature},
    signing::Signer,
};

pub struct ICSigner {
    public_key: Secp256k1PublicKey,
    key_info: KeyInfo,
}

thread_local! {
    // TODO: This is a temporary solution. We should use a more sophisticated way to return the signature.
    static CONTEXT: RefCell<HashMap<Vec<u8>,Secp256k1Signature>> = RefCell::new(HashMap::new());
}

impl ICSigner {
    pub async fn new(key_info: KeyInfo) -> Result<Self> {
        let pub_key = get_public_key(
            None,
            key_info.clone().derivation_path,
            key_info.clone().key_name,
        )
        .await
        .map_err(|e| anyhow::anyhow!(e))?;
        let secp256k1_pub_key = Secp256k1PublicKey::try_from(pub_key.as_slice())?;
        Ok(Self {
            public_key: secp256k1_pub_key,
            key_info,
        })
    }
}

fn put_to_context(hash: Vec<u8>, signature: Secp256k1Signature) {
    CONTEXT.with(|ctx| {
        ctx.borrow_mut().insert(hash, signature);
    });
}

fn get_from_context(hash: Vec<u8>) -> Option<Secp256k1Signature> {
    CONTEXT.with(|ctx| ctx.borrow().get(&hash).cloned())
}

fn remove_from_context(hash: Vec<u8>) {
    CONTEXT.with(|ctx| {
        ctx.borrow_mut().remove(&hash);
    });
}

impl Signer for ICSigner {
    fn public_key(&self) -> transaction::prelude::PublicKey {
        PublicKey::from(self.public_key)
    }

    fn sign_with_public_key(
        &self,
        message_hash: &impl transaction::prelude::IsHash,
    ) -> transaction::prelude::SignatureWithPublicKeyV1 {
        let hash_slice = message_hash.as_slice().to_vec();
        let hash = Box::new(hash_slice.clone());
        let key = Box::new(self.key_info.clone().to_owned());
        ic_cdk::spawn(async move {
            let sig = _sign(key, hash.clone()).await.unwrap();
            put_to_context(hash.as_slice().to_vec(), sig.clone());
        });
        let result = get_from_context(hash_slice.clone());
        remove_from_context(hash_slice);
        result.unwrap().into()
    }

    fn sign_without_public_key(
        &self,
        message_hash: &impl transaction::prelude::IsHash,
    ) -> transaction::prelude::SignatureV1 {
        let key = Box::new(self.key_info.clone().to_owned());
        let hash_slice = message_hash.as_slice().to_vec();
        let h = Box::new(hash_slice.clone());
        ic_cdk::spawn(async move {
            let sig = _sign(key, h.clone()).await.unwrap();
            put_to_context(h.as_slice().to_vec(), sig.clone());
        });
        let result = get_from_context(hash_slice.clone());
        remove_from_context(hash_slice);
        result.unwrap().into()
    }
}

async fn _sign(key_info: Box<KeyInfo>, message_hash: Box<Vec<u8>>) -> Result<Secp256k1Signature> {
    let sign_result = ic_raw_sign(*message_hash, *key_info)
        .await
        .map_err(|e| anyhow::anyhow!(e))?;

    Ok(Secp256k1Signature::try_from(sign_result.as_slice())?)
}

impl ICSigner {
    async fn _sign(&self, message_hash: &impl IsHash) -> anyhow::Result<Secp256k1Signature> {
        let key_info = self.key_info.clone().to_owned();
        let h = message_hash.as_slice().to_vec();
        let sign_result = ic_raw_sign(h, key_info)
            .await
            .map_err(|e| anyhow::anyhow!(e))?;

        Ok(Secp256k1Signature::try_from(sign_result.as_slice())?)
    }
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use transaction::prelude::{Hash, Secp256k1Signature};

    #[test]
    fn test_put_get_remove() {
        let hash =
            Hash::from_str("b177968c9c68877dc8d33e25759183c556379daa45a4d78a2b91c70133c873ca")
                .unwrap()
                .to_vec();
        // 65 bytes: message + recovery id
        let sig = vec![
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45,
            46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64,
        ];
        let signature = Secp256k1Signature::try_from(sig.as_slice()).unwrap();
        super::put_to_context(hash.clone(), signature.clone());
        let result = super::get_from_context(hash.clone());
        assert_eq!(result, Some(signature.clone()));
        super::remove_from_context(hash.clone());
        let result = super::get_from_context(hash.clone());
        assert_eq!(result, None);
    }
}
