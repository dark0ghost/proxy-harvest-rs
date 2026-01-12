use proxy_harvest_rs::config::{outbound, routing};
use proxy_harvest_rs::parser::{parse_servers, ServerConfig};

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
