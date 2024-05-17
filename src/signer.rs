use transaction::signing::Signer;

pub struct ICSigner {}

impl Signer for ICSigner {
    fn public_key(&self) -> transaction::prelude::PublicKey {
        unimplemented!()
    }
    fn sign_with_public_key(
        &self,
        message_hash: &impl transaction::prelude::IsHash,
    ) -> transaction::prelude::SignatureWithPublicKeyV1 {
        unimplemented!()
    }
    fn sign_without_public_key(
        &self,
        message_hash: &impl transaction::prelude::IsHash,
    ) -> transaction::prelude::SignatureV1 {
        unimplemented!()
    }
}
