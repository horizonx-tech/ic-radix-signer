use anyhow::Result;
use radix_transactions::model::HasSignedIntentHash;
use radix_transactions::model::TransactionPayload;
use radix_transactions::model::{
    IntentSignatureV1, IntentSignaturesV1, IntentV1, MessageV1, NotarizedTransactionV1,
    NotarySignatureV1, SignatureV1, SignatureWithPublicKeyV1, SignedIntentV1, TransactionHeaderV1,
    TransactionManifestV1,
};

use crate::signer::Signer;
use radix_transactions::model::HasIntentHash;

pub struct ICPTransactionBuilder {
    manifest: Option<TransactionManifestV1>,
    header: Option<TransactionHeaderV1>,
    message: Option<MessageV1>,
    intent_signatures: Vec<SignatureWithPublicKeyV1>,
    notary_signature: Option<SignatureV1>,
}

impl ICPTransactionBuilder {
    pub fn new() -> Self {
        Self {
            manifest: None,
            header: None,
            message: None,
            intent_signatures: vec![],
            notary_signature: None,
        }
    }
    pub fn manifest(mut self, manifest: TransactionManifestV1) -> Self {
        self.manifest = Some(manifest);
        self
    }

    pub fn header(mut self, header: TransactionHeaderV1) -> Self {
        self.header = Some(header);
        self
    }

    pub fn message(mut self, message: MessageV1) -> Self {
        self.message = Some(message);
        self
    }

    pub async fn sign<S: Signer>(mut self, signer: &S) -> Result<Self> {
        let intent = self.transaction_intent();
        let prepared = intent.prepare().expect("Intent could be prepared");
        self.intent_signatures
            .push(signer.sign_with_public_key(prepared.intent_hash()).await?);
        Ok(self)
    }

    pub async fn multi_sign<S: Signer>(mut self, signers: &[&S]) -> Result<Self> {
        let intent = self.transaction_intent();
        let prepared = intent.prepare().expect("Intent could be prepared");
        for signer in signers {
            self.intent_signatures
                .push(signer.sign_with_public_key(prepared.intent_hash()).await?);
        }
        Ok(self)
    }

    pub fn signer_signatures(mut self, sigs: Vec<SignatureWithPublicKeyV1>) -> Self {
        self.intent_signatures.extend(sigs);
        self
    }

    pub async fn notarize<S: Signer>(mut self, signer: &S) -> Result<Self> {
        let signed_intent = self.signed_transaction_intent();
        let prepared = signed_intent
            .prepare()
            .expect("Signed intent could be prepared");
        self.notary_signature = Some(
            signer
                .sign_with_public_key(prepared.signed_intent_hash())
                .await?
                .signature(),
        );
        Ok(self)
    }

    pub fn notary_signature(mut self, signature: SignatureV1) -> Self {
        self.notary_signature = Some(signature);
        self
    }

    pub fn build(&self) -> NotarizedTransactionV1 {
        NotarizedTransactionV1 {
            signed_intent: self.signed_transaction_intent(),
            notary_signature: NotarySignatureV1(
                self.notary_signature.clone().expect("Not notarized"),
            ),
        }
    }

    fn transaction_intent(&self) -> IntentV1 {
        let (instructions, blobs) = self
            .manifest
            .clone()
            .expect("Manifest not specified")
            .for_intent();
        IntentV1 {
            header: self.header.clone().expect("Header not specified"),
            instructions,
            blobs,
            message: self.message.clone().unwrap_or(MessageV1::None),
        }
    }

    fn signed_transaction_intent(&self) -> SignedIntentV1 {
        let intent = self.transaction_intent();
        SignedIntentV1 {
            intent,
            intent_signatures: IntentSignaturesV1 {
                signatures: self
                    .intent_signatures
                    .clone()
                    .into_iter()
                    .map(|sig| IntentSignatureV1(sig))
                    .collect(),
            },
        }
    }
}
