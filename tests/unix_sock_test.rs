mod common;
use common::*;

#[tokio::test]
async fn test_unix_suite() {
  #[cfg(unix)]
  {
    run_tcp_test("test_unix_normal", None, true).await;
    run_tcp_test("test_unix_proxy_v1", Some("v1"), true).await;
    run_tcp_test("test_unix_proxy_v2", Some("v2"), true).await;
  }
}
