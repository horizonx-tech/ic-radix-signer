#[ic_cdk::update]
async fn test_sign() -> String {
    format!("Hello, {}!", "test".to_string())
}
