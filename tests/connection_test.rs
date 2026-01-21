mod common;
use common::*;

#[tokio::test]
async fn test_tcp_normal() {
  run_tcp_test("test_tcp_normal", None, false).await;
}

#[tokio::test]
async fn test_http_normal() {
  run_http_test("test_http_normal", None, false, None, false, None).await;
}

#[tokio::test]
async fn test_https_normal() {
  run_http_test("test_https_normal", None, true, None, false, None).await;
}
