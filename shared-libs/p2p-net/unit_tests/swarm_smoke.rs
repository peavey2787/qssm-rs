use p2p_net::{start_node, NodeConfig};

#[tokio::test]
async fn node_start_shutdown_smoke() {
    let handle = start_node(NodeConfig::default()).await.expect("start node");
    handle.shutdown().await;
}
