#[cfg(all(windows, target_arch = "x86_64"))]
#[tokio::test]
async fn windows_tokio_boot_smoke() {
    let handle = p2p_net::start_node(p2p_net::NodeConfig::default())
        .await
        .expect("start node");
    handle.shutdown().await;
}
