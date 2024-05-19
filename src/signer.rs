use anyhow::Result;
use async_trait::async_trait;
use ic_web3_rs::ic::{get_public_key, ic_raw_sign, KeyInfo};
use radix_common::crypto::{IsHash, PublicKey, Secp256k1PublicKey, Secp256k1Signature};
use radix_transactions::model::{SignatureV1, SignatureWithPublicKeyV1};

pub struct ICSigner {
    public_key: Secp256k1PublicKey,
    key_info: KeyInfo,
}

#[async_trait]
pub trait Signer: Send + Sync {
    async fn public_key(&self) -> PublicKey;
    async fn sign_without_public_key(
        &self,
        message_hash: impl IsHash + Send,
    ) -> Result<SignatureV1>;
    async fn sign_with_public_key(
        &self,
        message_hash: impl IsHash + Send,
    ) -> Result<SignatureWithPublicKeyV1>;
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
#[async_trait]
impl Signer for ICSigner {
    async fn public_key(&self) -> PublicKey {
        PublicKey::from(self.public_key)
    }

    async fn sign_with_public_key(
        &self,
        message_hash: impl IsHash + Send,
    ) -> Result<SignatureWithPublicKeyV1> {
        let sig = self._sign(message_hash).await?;
        Ok(sig.into())
    }

    async fn sign_without_public_key(
        &self,
        message_hash: impl IsHash + Send,
    ) -> Result<SignatureV1> {
        let sig = self._sign(message_hash).await?;
        Ok(sig.into())
    }
}

impl ICSigner {
    async fn _sign(&self, message_hash: impl IsHash) -> anyhow::Result<Secp256k1Signature> {
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

    use radix_common::crypto::{Hash, Secp256k1Signature};

    #[test]
    fn test_put_get_remove() {}
}
