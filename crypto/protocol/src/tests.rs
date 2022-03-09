use crate::utils::test_context;

#[async_std::test]
async fn storage_get_current_timestamp() {
    let cxt = test_context().await;

    let timestamp = cxt.api.storage().timestamp().now(None).await;

    assert!(timestamp.is_ok())
}
