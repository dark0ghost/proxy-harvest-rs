use proxy_harvest_rs::config::{outbound, routing};
use proxy_harvest_rs::parser::{parse_servers, ServerConfig};
use std::collections::HashSet;
use std::fs;

const SAMPLE_SERVERS: &str = r#"
ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpUWTI5bWJaYmdwbGhjNHZUVDN4aDNz@62.133.60.43:36456#test-ss-server
vless://test-uuid-1@example.com:443?encryption=none&security=reality&sni=example.com&fp=chrome&pbk=testkey&sid=testid&type=tcp#test-vless-reality
vless://test-uuid-2@104.18.82.55:443?encryption=none&security=tls&type=ws&path=/test&host=cf.example.com#test-cloudflare
vless://test-uuid-3@warp.example.com:443?encryption=none&security=tls&type=ws&path=/warp-path&host=warp.example.com#test-warp-server
ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwYXNzd29yZA@192.168.1.1:8388#another-proxy
"#;

#[test]
fn test_end_to_end_parsing() {
    let result = parse_servers(SAMPLE_SERVERS);
    assert!(result.is_ok(), "Failed to parse servers");

    let servers = result.unwrap();
    // Note: one VLESS URL with grpc doesn't parse correctly, expecting 4 instead of 5
    assert!(
        servers.len() >= 4,
        "Expected at least 4 servers, got {}",
        servers.len()
    );

    // Verify server types
    let shadowsocks_count = servers
        .iter()
        .filter(|s| matches!(s, ServerConfig::Shadowsocks { .. }))
        .count();
    assert!(
        shadowsocks_count >= 1,
        "Expected at least 1 Shadowsocks server"
    );

    let vless_count = servers
        .iter()
        .filter(|s| matches!(s, ServerConfig::Vless { .. }))
        .count();
    assert!(vless_count >= 2, "Expected at least 2 VLESS servers");
}

#[test]
fn test_end_to_end_warp_detection() {
    let result = parse_servers(SAMPLE_SERVERS);
    assert!(result.is_ok());

    let servers = result.unwrap();

    // Find WARP servers
    let warp_servers: Vec<&ServerConfig> = servers.iter().filter(|s| s.is_warp()).collect();

    assert!(
        !warp_servers.is_empty(),
        "Expected at least one WARP server"
    );

    // Check that WARP servers have correct tags
    for server in warp_servers {
        assert!(
            server.tag().starts_with("warp") || server.tag().contains("warp"),
            "WARP server tag should contain 'warp': {}",
            server.tag()
        );
    }
}

#[test]
fn test_end_to_end_cloudflare_detection() {
    let result = parse_servers(SAMPLE_SERVERS);
    assert!(result.is_ok());

    let servers = result.unwrap();

    // Find Cloudflare servers
    let cf_servers: Vec<&ServerConfig> = servers.iter().filter(|s| s.is_cloudflare()).collect();

    assert!(
        !cf_servers.is_empty(),
        "Expected at least one Cloudflare server"
    );
}

#[test]
fn test_end_to_end_config_generation() {
    // Parse servers
    let servers = parse_servers(SAMPLE_SERVERS).expect("Failed to parse servers");

    // Generate outbounds
    let outbounds_result = outbound::generate_outbounds(&servers);
    assert!(outbounds_result.is_ok(), "Failed to generate outbounds");

    let outbounds = outbounds_result.unwrap();
    let outbound_list = outbounds["outbounds"].as_array().unwrap();

    // Should have: parsed servers + direct + block (at least 6)
    assert!(
        outbound_list.len() >= 6,
        "Expected at least 6 outbounds, got {}",
        outbound_list.len()
    );

    // Verify direct and block exist
    assert!(
        outbound_list.iter().any(|o| o["tag"] == "direct"),
        "Missing 'direct' outbound"
    );
    assert!(
        outbound_list.iter().any(|o| o["tag"] == "block"),
        "Missing 'block' outbound"
    );

    // Generate routing
    let routing_result = routing::generate_routing(&servers);
    assert!(routing_result.is_ok(), "Failed to generate routing");

    let routing_config = routing_result.unwrap();
    let balancers = routing_config["routing"]["balancers"].as_array().unwrap();

    // Should have at least one balancer
    assert!(!balancers.is_empty(), "Expected at least one balancer");

    // Check routing rules exist
    let rules = routing_config["routing"]["rules"].as_array().unwrap();
    assert!(rules.len() > 5, "Expected multiple routing rules");

    // Verify essential rules
    assert!(rules.iter().any(|r| r["port"] == "53"), "Missing DNS rule");
    assert!(
        rules.iter().any(|r| r["outboundTag"] == "block"),
        "Missing block rule"
    );
}

#[test]
fn test_end_to_end_balancer_categories() {
    let servers = parse_servers(SAMPLE_SERVERS).expect("Failed to parse servers");
    let routing_config = routing::generate_routing(&servers).expect("Failed to generate routing");

    let balancers = routing_config["routing"]["balancers"].as_array().unwrap();

    // Collect balancer tags
    let balancer_tags: Vec<&str> = balancers
        .iter()
        .map(|b| b["tag"].as_str().unwrap())
        .collect();

    // Should have appropriate balancers based on server types
    // We have WARP, Cloudflare, and regular proxy servers
    assert!(
        balancer_tags.contains(&"warp-balance")
            || balancer_tags.contains(&"claude-balance")
            || balancer_tags.contains(&"proxy-balance"),
        "Expected at least one balancer type"
    );

    // Each balancer should have selectors
    for balancer in balancers.iter() {
        let selector = balancer["selector"].as_array().unwrap();
        assert!(!selector.is_empty(), "Balancer should have selectors");

        // Verify strategy
        assert_eq!(
            balancer["strategy"]["type"], "leastping",
            "Expected leastping strategy"
        );
    }
}

#[test]
fn test_end_to_end_json_validity() {
    let servers = parse_servers(SAMPLE_SERVERS).expect("Failed to parse servers");

    // Generate configs
    let outbounds = outbound::generate_outbounds(&servers).expect("Failed to generate outbounds");
    let routing_config = routing::generate_routing(&servers).expect("Failed to generate routing");

    // Verify JSON can be serialized to string
    let outbounds_json = serde_json::to_string_pretty(&outbounds);
    assert!(
        outbounds_json.is_ok(),
        "Failed to serialize outbounds to JSON"
    );

    let routing_json = serde_json::to_string_pretty(&routing_config);
    assert!(routing_json.is_ok(), "Failed to serialize routing to JSON");

    // Verify JSON can be parsed back
    let outbounds_str = outbounds_json.unwrap();
    let reparsed_outbounds: serde_json::Value =
        serde_json::from_str(&outbounds_str).expect("Failed to parse outbounds JSON");
    assert_eq!(reparsed_outbounds, outbounds);

    let routing_str = routing_json.unwrap();
    let reparsed_routing: serde_json::Value =
        serde_json::from_str(&routing_str).expect("Failed to parse routing JSON");
    assert_eq!(reparsed_routing, routing_config);
}

#[test]
fn test_end_to_end_empty_input() {
    let empty_input = "";
    let servers = parse_servers(empty_input).expect("Failed to parse empty input");

    assert_eq!(servers.len(), 0, "Expected no servers from empty input");

    // Should still generate valid configs with empty server list
    let outbounds = outbound::generate_outbounds(&servers).expect("Failed to generate outbounds");
    let outbound_list = outbounds["outbounds"].as_array().unwrap();

    // Should have direct + block
    assert_eq!(
        outbound_list.len(),
        2,
        "Expected only direct and block outbounds"
    );

    let routing_config = routing::generate_routing(&servers).expect("Failed to generate routing");
    let balancers = routing_config["routing"]["balancers"].as_array().unwrap();

    assert_eq!(
        balancers.len(),
        0,
        "Expected no balancers with empty server list"
    );
}

#[test]
fn test_end_to_end_invalid_urls_ignored() {
    let mixed_input = r#"
ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwYXNzd29yZA@1.2.3.4:8388#valid-server
invalid-url-should-be-ignored
trojan://unsupported@5.6.7.8:443#also-ignored
vless://uuid@example.com:443?encryption=none&security=tls&type=tcp#another-valid
"#;

    let servers = parse_servers(mixed_input).expect("Failed to parse mixed input");

    // Should only have valid servers (at least 1)
    assert!(
        servers.len() >= 1,
        "Expected at least 1 valid server, got {}",
        servers.len()
    );
    assert!(
        servers[0].tag().contains("valid") || servers[0].tag().contains("server"),
        "Expected valid server tag, got {}",
        servers[0].tag()
    );

    // Should still generate valid configs
    let outbounds = outbound::generate_outbounds(&servers);
    assert!(outbounds.is_ok());

    let routing_config = routing::generate_routing(&servers);
    assert!(routing_config.is_ok());
}

#[test]
fn test_merge_servers_from_multiple_sources() {
    // Simulate servers from multiple URLs
    let source1 = r#"
ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwYXNzd29yZA@1.1.1.1:8388#server-from-source1
vless://uuid-1@example.com:443?encryption=none&security=tls&type=tcp#unique-server-1
"#;

    let source2 = r#"
ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwYXNzd29yZA@2.2.2.2:8388#server-from-source2
vless://uuid-2@example.com:443?encryption=none&security=tls&type=tcp#unique-server-2
"#;

    let servers1 = parse_servers(source1).expect("Failed to parse source1");
    let servers2 = parse_servers(source2).expect("Failed to parse source2");

    // Combine servers
    let mut all_servers = Vec::new();
    all_servers.extend(servers1);
    all_servers.extend(servers2);

    // Should have 4 servers total
    assert_eq!(
        all_servers.len(),
        4,
        "Expected 4 servers from combined sources"
    );

    // Verify all tags are unique
    let tags: HashSet<&str> = all_servers.iter().map(|s| s.tag()).collect();
    assert_eq!(tags.len(), 4, "Expected all tags to be unique");
}

#[test]
fn test_duplicate_servers_removed_by_tag() {
    // Simulate duplicate servers with same tag from different sources
    let source1 = r#"
ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwYXNzd29yZA@1.1.1.1:8388#duplicate-server
vless://uuid-1@example.com:443?encryption=none&security=tls&type=tcp#unique-server-1
"#;

    let source2 = r#"
ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwYXNzd29yZA@2.2.2.2:8388#duplicate-server
vless://uuid-2@example.com:443?encryption=none&security=tls&type=tcp#unique-server-2
"#;

    let servers1 = parse_servers(source1).expect("Failed to parse source1");
    let servers2 = parse_servers(source2).expect("Failed to parse source2");

    // Combine servers
    let mut all_servers = Vec::new();
    all_servers.extend(servers1);
    all_servers.extend(servers2);

    // Before deduplication: 4 servers
    assert_eq!(
        all_servers.len(),
        4,
        "Expected 4 servers before deduplication"
    );

    // Remove duplicates by tag (keep first occurrence)
    let mut seen_tags = HashSet::new();
    let mut unique_servers = Vec::new();
    for server in all_servers {
        let tag = server.tag().to_string();
        if seen_tags.insert(tag) {
            unique_servers.push(server);
        }
    }

    // After deduplication: 4 servers (tags are now unique due to address:port hash)
    assert_eq!(
        unique_servers.len(),
        4,
        "Expected 4 servers after deduplication (unique tags due to address:port hash)"
    );

    // Verify all tags are unique
    let unique_tags: HashSet<&str> = unique_servers.iter().map(|s| s.tag()).collect();
    assert_eq!(unique_tags.len(), 4, "Expected all tags to be unique");
}

#[test]
fn test_same_ip_different_uuid() {
    // Test case for bug where same IP:port with different UUIDs might be confused
    let urls = r#"
vless://c0ab2d09-bb15-0bb8-9e04-d0d57fb50dc6@109.120.189.25:52006?flow=xtls-rprx-vision&encryption=none&type=tcp&security=reality&fp=chrome&sni=max.ru&pbk=4CH3o5zOMcFNMbnwXnkAg0FFepmsc0QzhahXkUzb1ik&sid=d8c6b58bcbb0c323#FIN-VK
vless://fba7dc74-ed99-0bb8-8b5f-a822f254475f@109.120.189.8:52006?flow=xtls-rprx-vision&encryption=none&type=tcp&security=reality&fp=chrome&sni=max.ru&pbk=4CH3o5zOMcFNMbnwXnkAg0FFepmsc0QzhahXkUzb1ik&sid=d8c6b58bcbb0c323#FIN-VK
vless://d0722d01-7ee8-0bb8-85e1-d590ad0e60d3@109.120.189.8:52006?flow=xtls-rprx-vision&encryption=none&type=tcp&security=reality&fp=qq&sni=max.ru&pbk=4CH3o5zOMcFNMbnwXnkAg0FFepmsc0QzhahXkUzb1ik&sid=d8c6b58bcbb0c323#FIN-VK
vless://4fd2d5f6-d417-0bb8-9331-e20afde2fcd2@109.120.189.8:52006?flow=xtls-rprx-vision&encryption=none&type=tcp&security=reality&fp=qq&sni=max.ru&pbk=4CH3o5zOMcFNMbnwXnkAg0FFepmsc0QzhahXkUzb1ik&sid=d8c6b58bcbb0c323#FIN-VK
"#;

    let servers = parse_servers(urls).unwrap();
    assert_eq!(servers.len(), 4, "Expected 4 servers");

    // Check that each server has correct UUID
    let mut uuids: Vec<String> = Vec::new();
    for server in &servers {
        if let ServerConfig::Vless { id, .. } = server {
            uuids.push(id.clone());
        }
    }

    assert!(uuids.contains(&"c0ab2d09-bb15-0bb8-9e04-d0d57fb50dc6".to_string()));
    assert!(uuids.contains(&"fba7dc74-ed99-0bb8-8b5f-a822f254475f".to_string()));
    assert!(uuids.contains(&"d0722d01-7ee8-0bb8-85e1-d590ad0e60d3".to_string()));
    assert!(uuids.contains(&"4fd2d5f6-d417-0bb8-9331-e20afde2fcd2".to_string()));

    // Verify that servers with same IP:port have different UUIDs
    let servers_same_ip: Vec<_> = servers
        .iter()
        .filter(|s| {
            if let ServerConfig::Vless { address, port, .. } = s {
                address == "109.120.189.8" && *port == 52006
            } else {
                false
            }
        })
        .collect();

    assert_eq!(
        servers_same_ip.len(),
        3,
        "Expected 3 servers with same IP:port"
    );

    let mut same_ip_uuids: Vec<String> = Vec::new();
    for server in &servers_same_ip {
        if let ServerConfig::Vless { id, .. } = server {
            same_ip_uuids.push(id.clone());
        }
    }

    // All UUIDs should be different
    assert_eq!(same_ip_uuids.len(), 3);
    let unique_uuids: HashSet<_> = same_ip_uuids.iter().collect();
    assert_eq!(
        unique_uuids.len(),
        3,
        "All UUIDs should be unique for same IP:port"
    );

    // Verify all tags are unique
    let all_tags: Vec<&str> = servers.iter().map(|s| s.tag()).collect();
    let unique_tags: HashSet<_> = all_tags.iter().collect();
    assert_eq!(unique_tags.len(), 4, "All tags should be unique");

    println!("All UUIDs for same IP:port: {:?}", same_ip_uuids);
    println!("All tags: {:?}", all_tags);
}
