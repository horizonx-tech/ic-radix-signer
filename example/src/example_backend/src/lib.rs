#[ic_cdk::update]
async fn test_sign() -> String {
    format!("Hello, {}!", name)
}
