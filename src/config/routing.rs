use crate::parser::ServerConfig;
use anyhow::Result;
use serde_json::{json, Value};

pub fn generate_routing(servers: &[ServerConfig]) -> Result<Value> {
    // Separate servers into different categories
    let mut warp_servers = Vec::new();
    let mut cloudflare_servers = Vec::new();
    let mut proxy_servers = Vec::new();

    for server in servers {
        let tag = server.tag().to_string();
        if server.is_warp() {
            warp_servers.push(tag);
        } else if server.is_cloudflare() {
            cloudflare_servers.push(tag);
        } else {
            proxy_servers.push(tag);
        }
    }

    // Create balancers
    let mut balancers = Vec::new();

    if !cloudflare_servers.is_empty() {
        balancers.push(json!({
            "tag": "claude-balance",
            "selector": cloudflare_servers,
            "strategy": {
                "type": "leastping"
            }
        }));
    }

    if !warp_servers.is_empty() {
        balancers.push(json!({
            "tag": "warp-balance",
            "selector": warp_servers,
            "strategy": {
                "type": "leastping"
            }
        }));
    }

    if !proxy_servers.is_empty() {
        balancers.push(json!({
            "tag": "proxy-balance",
            "selector": proxy_servers,
            "strategy": {
                "type": "leastping"
            }
        }));
    }

    // Create routing rules
    let rules = vec![
        // DNS queries go direct
        json!({
            "type": "field",
            "inboundTag": ["redirect", "tproxy"],
            "outboundTag": "direct",
            "port": "53"
        }),
        // Block NetBIOS
        json!({
            "type": "field",
            "inboundTag": ["redirect", "tproxy"],
            "outboundTag": "block",
            "network": "udp",
            "port": "135,137,138,139"
        }),
        // Block ads
        json!({
            "type": "field",
            "inboundTag": ["redirect", "tproxy"],
            "outboundTag": "block",
            "domain": [
                "ext:geosite_v2fly.dat:category-ads-all",
                "domain:pagead2.googlesyndication.com",
                "domain:googleads.g.doubleclick.net",
                "domain:ad.adriver.ru",
                "domain:pink.habralab.ru",
                "domain:www.google-analytics.com",
                "domain:ssl.google-analytics.com",
                "analytics.yandex",
                "appcenter.ms",
                "app-measurement.com",
                "firebase.io",
                "crashlytics.com"
            ]
        }),
    ];

    let mut routing_rules = rules;

    // Add balancer rules
    if !cloudflare_servers.is_empty() {
        routing_rules.push(json!({
            "type": "field",
            "inboundTag": ["redirect", "tproxy"],
            "balancerTag": "claude-balance",
            "domain": []
        }));
    }

    if !warp_servers.is_empty() {
        routing_rules.push(json!({
            "type": "field",
            "inboundTag": ["redirect", "tproxy"],
            "balancerTag": "warp-balance",
            "domain": []
        }));
    }

    if !proxy_servers.is_empty() {
        routing_rules.push(json!({
            "type": "field",
            "inboundTag": ["redirect", "tproxy"],
            "balancerTag": "proxy-balance",
            "domain": []
        }));
    }

    // BitTorrent goes direct
    routing_rules.push(json!({
        "type": "field",
        "inboundTag": ["redirect", "tproxy"],
        "outboundTag": "direct",
        "protocol": ["bittorrent"]
    }));

    // Local IPs go direct
    routing_rules.push(json!({
        "type": "field",
        "inboundTag": ["redirect", "tproxy"],
        "outboundTag": "direct",
        "ip": [
            "127.0.0.0/8",
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "169.254.0.0/16",
            "::1/128",
            "fc00::/7",
            "fe80::/10"
        ]
    }));

    // Default rule - use proxy balance if available, otherwise direct
    let default_tag = if !proxy_servers.is_empty() {
        "proxy-balance"
    } else if !cloudflare_servers.is_empty() {
        "claude-balance"
    } else if !warp_servers.is_empty() {
        "warp-balance"
    } else {
        "direct"
    };

    routing_rules.push(json!({
        "type": "field",
        "inboundTag": ["redirect", "tproxy"],
        "outboundTag": default_tag,
        "network": "tcp,udp"
    }));

    Ok(json!({
        "routing": {
            "domainStrategy": "IPIfNonMatch",
            "rules": routing_rules,
            "balancers": balancers
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::ServerConfig;

    #[test]
    fn test_generate_routing_with_warp_servers() {
        let servers = vec![
            ServerConfig::Shadowsocks {
                tag: "warp-test".to_string(),
                address: "1.2.3.4".to_string(),
                port: 8388,
                method: "aes-256-gcm".to_string(),
                password: "test".to_string(),
            },
            ServerConfig::Shadowsocks {
                tag: "normal-server".to_string(),
                address: "5.6.7.8".to_string(),
                port: 8388,
                method: "aes-256-gcm".to_string(),
                password: "test".to_string(),
            },
        ];

        let result = generate_routing(&servers);
        assert!(result.is_ok());

        let config = result.unwrap();
        let balancers = config["routing"]["balancers"].as_array().unwrap();

        // Should have warp-balance and proxy-balance
        assert_eq!(balancers.len(), 2);

        let warp_balance = balancers
            .iter()
            .find(|b| b["tag"] == "warp-balance")
            .expect("warp-balance not found");

        assert_eq!(warp_balance["selector"].as_array().unwrap().len(), 1);
        assert_eq!(warp_balance["selector"][0], "warp-test");
    }

    #[test]
    fn test_generate_routing_with_cloudflare_servers() {
        let servers = vec![ServerConfig::Vless {
            tag: "cf-server".to_string(),
            address: "104.18.82.55".to_string(),
            port: 443,
            id: "test-uuid".to_string(),
            encryption: "none".to_string(),
            flow: "".to_string(),
            network: "tcp".to_string(),
            security: "tls".to_string(),
            tls_settings: None,
            network_settings: None,
        }];

        let result = generate_routing(&servers);
        assert!(result.is_ok());

        let config = result.unwrap();
        let balancers = config["routing"]["balancers"].as_array().unwrap();

        // Should have claude-balance
        let claude_balance = balancers
            .iter()
            .find(|b| b["tag"] == "claude-balance")
            .expect("claude-balance not found");

        assert_eq!(claude_balance["selector"].as_array().unwrap().len(), 1);
        assert_eq!(claude_balance["selector"][0], "cf-server");
    }

    #[test]
    fn test_generate_routing_rules_structure() {
        let servers = vec![];

        let result = generate_routing(&servers);
        assert!(result.is_ok());

        let config = result.unwrap();
        let rules = config["routing"]["rules"].as_array().unwrap();

        // Should have at least: DNS, NetBIOS, ads, bittorrent, local IPs, default
        assert!(rules.len() >= 6);

        // Check DNS rule
        let dns_rule = &rules[0];
        assert_eq!(dns_rule["port"], "53");
        assert_eq!(dns_rule["outboundTag"], "direct");

        // Check ads blocking rule
        let ads_rule = &rules[2];
        assert_eq!(ads_rule["outboundTag"], "block");
        assert!(ads_rule["domain"].as_array().unwrap().len() > 0);

        // Check local IPs rule
        let local_rule = rules
            .iter()
            .find(|r| r["ip"].is_array() && r["outboundTag"] == "direct")
            .expect("Local IPs rule not found");

        let local_ips = local_rule["ip"].as_array().unwrap();
        assert!(local_ips.iter().any(|ip| ip == "127.0.0.0/8"));
        assert!(local_ips.iter().any(|ip| ip == "192.168.0.0/16"));
    }

    #[test]
    fn test_generate_routing_default_tag() {
        // Test with only proxy servers
        let proxy_servers = vec![ServerConfig::Shadowsocks {
            tag: "proxy1".to_string(),
            address: "1.2.3.4".to_string(),
            port: 8388,
            method: "aes-256-gcm".to_string(),
            password: "test".to_string(),
        }];

        let result = generate_routing(&proxy_servers).unwrap();
        let rules = result["routing"]["rules"].as_array().unwrap();
        let default_rule = rules.last().unwrap();

        // When proxy servers exist, default should use proxy-balance
        assert!(
            default_rule["outboundTag"] == "proxy-balance"
                || default_rule["balancerTag"] == "proxy-balance"
        );
    }

    #[test]
    fn test_generate_routing_empty_servers() {
        let servers = vec![];

        let result = generate_routing(&servers);
        assert!(result.is_ok());

        let config = result.unwrap();
        let balancers = config["routing"]["balancers"].as_array().unwrap();

        // Should have no balancers
        assert_eq!(balancers.len(), 0);

        let rules = config["routing"]["rules"].as_array().unwrap();
        let default_rule = rules.last().unwrap();

        // With no servers, default should be direct
        assert_eq!(default_rule["outboundTag"], "direct");
    }

    #[test]
    fn test_generate_routing_mixed_servers() {
        let servers = vec![
            ServerConfig::Shadowsocks {
                tag: "warp-1".to_string(),
                address: "1.1.1.1".to_string(),
                port: 8388,
                method: "aes-256-gcm".to_string(),
                password: "test".to_string(),
            },
            ServerConfig::Vless {
                tag: "cf-1".to_string(),
                address: "104.18.82.55".to_string(),
                port: 443,
                id: "test-uuid".to_string(),
                encryption: "none".to_string(),
                flow: "".to_string(),
                network: "tcp".to_string(),
                security: "tls".to_string(),
                tls_settings: None,
                network_settings: None,
            },
            ServerConfig::Shadowsocks {
                tag: "proxy-1".to_string(),
                address: "8.8.8.8".to_string(),
                port: 8388,
                method: "aes-256-gcm".to_string(),
                password: "test".to_string(),
            },
        ];

        let result = generate_routing(&servers);
        assert!(result.is_ok());

        let config = result.unwrap();
        let balancers = config["routing"]["balancers"].as_array().unwrap();

        // Should have all three balancers
        assert_eq!(balancers.len(), 3);

        let tags: Vec<&str> = balancers
            .iter()
            .map(|b| b["tag"].as_str().unwrap())
            .collect();

        assert!(tags.contains(&"warp-balance"));
        assert!(tags.contains(&"claude-balance"));
        assert!(tags.contains(&"proxy-balance"));
    }
}
