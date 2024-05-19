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
mod test {}
