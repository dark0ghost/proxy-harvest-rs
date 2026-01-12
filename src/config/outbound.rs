use crate::parser::{NetworkSettings, ServerConfig};
use anyhow::Result;
use serde_json::{Value, json};

pub fn generate_outbounds(servers: &[ServerConfig]) -> Result<Value> {
    let mut outbounds = Vec::new();

    // Add all parsed servers
    for server in servers {
        let outbound = match server {
            ServerConfig::Shadowsocks {
                tag,
                address,
                port,
                method,
                password,
            } => {
                json!({
                    "tag": tag,
                    "protocol": "shadowsocks",
                    "settings": {
                        "servers": [
                            {
                                "address": address,
                                "port": port,
                                "method": method,
                                "password": password
                            }
                        ]
                    }
                })
            }
            ServerConfig::Vless {
                tag,
                address,
                port,
                id,
                encryption,
                flow,
                network,
                security,
                tls_settings,
                network_settings,
            } => {
                let mut outbound = json!({
                    "tag": tag,
                    "protocol": "vless",
                    "settings": {
                        "vnext": [
                            {
                                "address": address,
                                "port": port,
                                "users": [
                                    {
                                        "id": id,
                                        "flow": flow,
                                        "encryption": encryption,
                                        "level": 0
                                    }
                                ]
                            }
                        ]
                    }
                });

                // Build stream settings
                let mut stream_settings = json!({
                    "network": network,
                    "security": security
                });

                // Add TLS/Reality settings
                if let Some(tls) = &**tls_settings {
                    if security == "reality" {
                        let mut reality_settings = json!({
                            "fingerprint": tls.fingerprint,
                            "serverName": tls.server_name
                        });

                        if let Some(ref pk) = tls.public_key {
                            reality_settings["publicKey"] = json!(pk);
                        }
                        if let Some(ref sid) = tls.short_id {
                            reality_settings["shortId"] = json!(sid);
                        }
                        if let Some(ref spx) = tls.spider_x {
                            reality_settings["spiderX"] = json!(spx);
                        }

                        stream_settings["realitySettings"] = reality_settings;
                    } else if security == "tls" {
                        let mut tls_settings_json = json!({
                            "fingerprint": tls.fingerprint,
                            "serverName": tls.server_name,
                            "allowInsecure": tls.allow_insecure
                        });

                        if let Some(ref alpn) = tls.alpn {
                            tls_settings_json["alpn"] = json!(alpn);
                        }

                        stream_settings["tlsSettings"] = tls_settings_json;
                    }
                }

                // Add network settings
                if let Some(net) = network_settings {
                    match net {
                        NetworkSettings::WebSocket { path, host } => {
                            stream_settings["wsSettings"] = json!({
                                "path": path,
                                "host": host
                            });
                        }
                        NetworkSettings::Grpc {
                            service_name,
                            authority,
                        } => {
                            stream_settings["grpcSettings"] = json!({
                                "serviceName": service_name,
                                "authority": authority,
                                "multiMode": false
                            });
                        }
                        NetworkSettings::Tcp { header_type } => {
                            stream_settings["tcpSettings"] = json!({
                                "header": {
                                    "type": header_type
                                }
                            });
                        }
                    }
                }

                outbound["streamSettings"] = stream_settings;
                outbound
            }
            ServerConfig::Vmess {
                tag,
                address,
                port,
                id,
                alter_id,
                security,
                network,
                network_settings,
                tls_settings,
                allow_insecure,
            } => {
                let mut outbound = json!({
                    "tag": tag,
                    "protocol": "vmess",
                    "settings": {
                        "vnext": [
                            {
                                "address": address,
                                "port": port,
                                "users": [
                                    {
                                        "id": id,
                                        "alterId": alter_id,
                                        "security": security,
                                        "level": 0
                                    }
                                ]
                            }
                        ]
                    }
                });

                // Build stream settings for Vmess
                let mut stream_settings = json!({
                    "network": network
                });

                // Add TLS settings if needed
                let security_type = if let Some(tls) = &**tls_settings {
                    if !tls.server_name.is_empty() {
                        "tls"
                    } else {
                        "none"
                    }
                } else {
                    "none"
                };

                stream_settings["security"] = json!(security_type);

                if security_type == "tls" {
                    if let Some(tls) = &**tls_settings {
                        let mut tls_settings_json = json!({
                            "serverName": tls.server_name,
                            "allowInsecure": *allow_insecure || tls.allow_insecure
                        });

                        if !tls.fingerprint.is_empty() && tls.fingerprint != "none" {
                            tls_settings_json["fingerprint"] = json!(tls.fingerprint);
                        }

                        if let Some(ref alpn) = tls.alpn {
                            if !alpn.is_empty() {
                                tls_settings_json["alpn"] = json!(alpn);
                            }
                        }

                        stream_settings["tlsSettings"] = tls_settings_json;
                    }
                }

                // Add network settings
                if let Some(net) = network_settings {
                    match net {
                        NetworkSettings::WebSocket { path, host } => {
                            stream_settings["wsSettings"] = json!({
                                "path": path,
                                "headers": {
                                    "Host": host
                                }
                            });
                        }
                        NetworkSettings::Grpc {
                            service_name,
                            authority,
                        } => {
                            stream_settings["grpcSettings"] = json!({
                                "serviceName": service_name,
                                "authority": authority,
                                "multiMode": false
                            });
                        }
                        NetworkSettings::Tcp { header_type } => {
                            if header_type != "none" {
                                stream_settings["tcpSettings"] = json!({
                                    "header": {
                                        "type": header_type
                                    }
                                });
                            }
                        }
                    }
                }

                outbound["streamSettings"] = stream_settings;
                outbound
            }
            ServerConfig::Trojan {
                tag,
                address,
                port,
                password,
                network,
                security,
                tls_settings,
                network_settings,
                allow_insecure,
            } => {
                let mut outbound = json!({
                    "tag": tag,
                    "protocol": "trojan",
                    "settings": {
                        "servers": [
                            {
                                "address": address,
                                "port": port,
                                "password": password,
                                "level": 0
                            }
                        ]
                    }
                });

                // Build stream settings
                let mut stream_settings = json!({
                    "network": network,
                    "security": security
                });

                // Add TLS settings
                if security == "tls" {
                    if let Some(tls) = &**tls_settings {
                        let mut tls_settings_json = json!({
                            "serverName": tls.server_name,
                            "allowInsecure": *allow_insecure || tls.allow_insecure
                        });

                        if !tls.fingerprint.is_empty() && tls.fingerprint != "none" {
                            tls_settings_json["fingerprint"] = json!(tls.fingerprint);
                        }

                        if let Some(ref alpn) = tls.alpn {
                            if !alpn.is_empty() {
                                tls_settings_json["alpn"] = json!(alpn);
                            }
                        }

                        stream_settings["tlsSettings"] = tls_settings_json;
                    }
                }

                // Add network settings
                if let Some(net) = network_settings {
                    match net {
                        NetworkSettings::WebSocket { path, host } => {
                            stream_settings["wsSettings"] = json!({
                                "path": path,
                                "headers": {
                                    "Host": host
                                }
                            });
                        }
                        NetworkSettings::Grpc {
                            service_name,
                            authority,
                        } => {
                            stream_settings["grpcSettings"] = json!({
                                "serviceName": service_name,
                                "authority": authority,
                                "multiMode": false
                            });
                        }
                        NetworkSettings::Tcp { header_type } => {
                            if header_type != "none" {
                                stream_settings["tcpSettings"] = json!({
                                    "header": {
                                        "type": header_type
                                    }
                                });
                            }
                        }
                    }
                }

                outbound["streamSettings"] = stream_settings;
                outbound
            }
            ServerConfig::Hysteria2 {
                tag,
                address,
                port,
                password,
                server_name,
                allow_insecure,
                obfs,
                obfs_password,
            } => {
                let mut settings = json!({
                    "auth": password,
                    "server": address,
                    "serverPort": port,
                    "tls": {
                        "enabled": true,
                        "serverName": server_name,
                        "insecure": allow_insecure
                    }
                });

                // Add obfs settings if present
                if let Some(obfs_type) = obfs {
                    settings["obfs"] = json!({
                        "type": obfs_type,
                        "password": obfs_password.as_ref().map(|s| s.as_str()).unwrap_or("")
                    });
                }

                json!({
                    "tag": tag,
                    "protocol": "hysteria",
                    "settings": settings
                })
            }
        };

        outbounds.push(outbound);
    }

    // Add standard outbounds
    outbounds.push(json!({
        "tag": "direct",
        "protocol": "freedom"
    }));

    outbounds.push(json!({
        "tag": "block",
        "protocol": "blackhole",
        "settings": {
            "response": {
                "type": "http"
            }
        }
    }));

    Ok(json!({
        "outbounds": outbounds
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::{NetworkSettings, ServerConfig, TlsSettings};

    #[test]
    fn test_generate_outbounds_shadowsocks() {
        let servers = vec![ServerConfig::Shadowsocks {
            tag: "test-ss".to_string(),
            address: "1.2.3.4".to_string(),
            port: 8388,
            method: "aes-256-gcm".to_string(),
            password: "test-password".to_string(),
        }];

        let result = generate_outbounds(&servers);
        assert!(result.is_ok());

        let config = result.unwrap();
        let outbounds = config["outbounds"].as_array().unwrap();

        // Should have: 1 server + direct + block = 3 outbounds
        assert_eq!(outbounds.len(), 3);

        // Check shadowsocks server
        let ss = &outbounds[0];
        assert_eq!(ss["tag"], "test-ss");
        assert_eq!(ss["protocol"], "shadowsocks");
        assert_eq!(ss["settings"]["servers"][0]["address"], "1.2.3.4");
        assert_eq!(ss["settings"]["servers"][0]["port"], 8388);
        assert_eq!(ss["settings"]["servers"][0]["method"], "aes-256-gcm");
    }

    #[test]
    fn test_generate_outbounds_vless_reality() {
        let servers = vec![ServerConfig::Vless {
            tag: "test-vless".to_string(),
            address: "example.com".to_string(),
            port: 443,
            id: "test-uuid".to_string(),
            encryption: "none".to_string(),
            flow: "xtls-rprx-vision".to_string(),
            network: "tcp".to_string(),
            security: "reality".to_string(),
            tls_settings: Box::new(Some(TlsSettings {
                server_name: "example.com".to_string(),
                fingerprint: "chrome".to_string(),
                alpn: None,
                allow_insecure: false,
                public_key: Some("test-key".to_string()),
                short_id: Some("test-id".to_string()),
                spider_x: Some("/".to_string()),
            })),
            network_settings: Some(NetworkSettings::Tcp {
                header_type: "none".to_string(),
            }),
        }];

        let result = generate_outbounds(&servers);
        assert!(result.is_ok());

        let config = result.unwrap();
        let outbounds = config["outbounds"].as_array().unwrap();

        let vless = &outbounds[0];
        assert_eq!(vless["tag"], "test-vless");
        assert_eq!(vless["protocol"], "vless");
        assert_eq!(vless["streamSettings"]["security"], "reality");
        assert_eq!(
            vless["streamSettings"]["realitySettings"]["publicKey"],
            "test-key"
        );
        assert_eq!(
            vless["streamSettings"]["realitySettings"]["shortId"],
            "test-id"
        );
    }

    #[test]
    fn test_generate_outbounds_includes_standard() {
        let servers = vec![];

        let result = generate_outbounds(&servers);
        assert!(result.is_ok());

        let config = result.unwrap();
        let outbounds = config["outbounds"].as_array().unwrap();

        // Should have direct + block
        assert_eq!(outbounds.len(), 2);

        let direct = &outbounds[0];
        assert_eq!(direct["tag"], "direct");
        assert_eq!(direct["protocol"], "freedom");

        let block = &outbounds[1];
        assert_eq!(block["tag"], "block");
        assert_eq!(block["protocol"], "blackhole");
    }

    #[test]
    fn test_generate_outbounds_vless_websocket() {
        let servers = vec![ServerConfig::Vless {
            tag: "ws-server".to_string(),
            address: "example.com".to_string(),
            port: 443,
            id: "test-uuid".to_string(),
            encryption: "none".to_string(),
            flow: "".to_string(),
            network: "ws".to_string(),
            security: "tls".to_string(),
            tls_settings: Box::new(Some(TlsSettings {
                server_name: "example.com".to_string(),
                fingerprint: "chrome".to_string(),
                alpn: Some(vec!["h2".to_string(), "http/1.1".to_string()]),
                allow_insecure: true,
                public_key: None,
                short_id: None,
                spider_x: None,
            })),
            network_settings: Some(NetworkSettings::WebSocket {
                path: "/ws".to_string(),
                host: "example.com".to_string(),
            }),
        }];

        let result = generate_outbounds(&servers);
        assert!(result.is_ok());

        let config = result.unwrap();
        let outbounds = config["outbounds"].as_array().unwrap();

        let vless = &outbounds[0];
        assert_eq!(vless["streamSettings"]["network"], "ws");
        assert_eq!(vless["streamSettings"]["wsSettings"]["path"], "/ws");
        assert_eq!(vless["streamSettings"]["wsSettings"]["host"], "example.com");
        assert_eq!(vless["streamSettings"]["tlsSettings"]["alpn"][0], "h2");
    }

    #[test]
    fn test_generate_outbounds_vmess_basic() {
        let servers = vec![ServerConfig::Vmess {
            tag: "vmess-server".to_string(),
            address: "example.com".to_string(),
            port: 443,
            id: "test-uuid".to_string(),
            alter_id: 0,
            security: "auto".to_string(),
            network: "tcp".to_string(),
            network_settings: None,
            tls_settings: Box::new(None),
            allow_insecure: false,
        }];

        let result = generate_outbounds(&servers);
        assert!(result.is_ok());

        let config = result.unwrap();
        let outbounds = config["outbounds"].as_array().unwrap();

        let vmess = &outbounds[0];
        assert_eq!(vmess["tag"], "vmess-server");
        assert_eq!(vmess["protocol"], "vmess");
        assert_eq!(vmess["settings"]["vnext"][0]["address"], "example.com");
        assert_eq!(vmess["settings"]["vnext"][0]["port"], 443);
        assert_eq!(vmess["settings"]["vnext"][0]["users"][0]["id"], "test-uuid");
        assert_eq!(vmess["settings"]["vnext"][0]["users"][0]["alterId"], 0);
        assert_eq!(
            vmess["settings"]["vnext"][0]["users"][0]["security"],
            "auto"
        );
    }

    #[test]
    fn test_generate_outbounds_vmess_websocket_tls() {
        let tls_settings = Some(TlsSettings {
            server_name: "example.com".to_string(),
            fingerprint: "chrome".to_string(),
            alpn: Some(vec!["http/1.1".to_string()]),
            allow_insecure: false,
            public_key: None,
            short_id: None,
            spider_x: None,
        });

        let servers = vec![ServerConfig::Vmess {
            tag: "vmess-ws".to_string(),
            address: "example.com".to_string(),
            port: 443,
            id: "test-uuid".to_string(),
            alter_id: 0,
            security: "auto".to_string(),
            network: "ws".to_string(),
            network_settings: Some(NetworkSettings::WebSocket {
                path: "/websocket".to_string(),
                host: "example.com".to_string(),
            }),
            tls_settings: Box::new(tls_settings),
            allow_insecure: false,
        }];

        let result = generate_outbounds(&servers);
        assert!(result.is_ok());

        let config = result.unwrap();
        let outbounds = config["outbounds"].as_array().unwrap();

        let vmess = &outbounds[0];
        assert_eq!(vmess["streamSettings"]["network"], "ws");
        assert_eq!(vmess["streamSettings"]["security"], "tls");
        assert_eq!(vmess["streamSettings"]["wsSettings"]["path"], "/websocket");
        assert_eq!(
            vmess["streamSettings"]["wsSettings"]["headers"]["Host"],
            "example.com"
        );
        assert_eq!(
            vmess["streamSettings"]["tlsSettings"]["serverName"],
            "example.com"
        );
        assert_eq!(
            vmess["streamSettings"]["tlsSettings"]["alpn"][0],
            "http/1.1"
        );
    }

    #[test]
    fn test_generate_outbounds_trojan_basic() {
        let servers = vec![ServerConfig::Trojan {
            tag: "trojan-server".to_string(),
            address: "example.com".to_string(),
            port: 443,
            password: "test-password".to_string(),
            network: "tcp".to_string(),
            security: "tls".to_string(),
            tls_settings: Box::new(Some(TlsSettings {
                server_name: "example.com".to_string(),
                fingerprint: "chrome".to_string(),
                alpn: None,
                allow_insecure: false,
                public_key: None,
                short_id: None,
                spider_x: None,
            })),
            network_settings: None,
            allow_insecure: false,
        }];

        let result = generate_outbounds(&servers);
        assert!(result.is_ok());

        let config = result.unwrap();
        let outbounds = config["outbounds"].as_array().unwrap();

        let trojan = &outbounds[0];
        assert_eq!(trojan["tag"], "trojan-server");
        assert_eq!(trojan["protocol"], "trojan");
        assert_eq!(trojan["settings"]["servers"][0]["address"], "example.com");
        assert_eq!(trojan["settings"]["servers"][0]["port"], 443);
        assert_eq!(
            trojan["settings"]["servers"][0]["password"],
            "test-password"
        );
        assert_eq!(trojan["streamSettings"]["security"], "tls");
    }

    #[test]
    fn test_generate_outbounds_trojan_websocket() {
        let servers = vec![ServerConfig::Trojan {
            tag: "trojan-ws".to_string(),
            address: "example.com".to_string(),
            port: 443,
            password: "test-password".to_string(),
            network: "ws".to_string(),
            security: "tls".to_string(),
            tls_settings: Box::new(Some(TlsSettings {
                server_name: "example.com".to_string(),
                fingerprint: "chrome".to_string(),
                alpn: None,
                allow_insecure: false,
                public_key: None,
                short_id: None,
                spider_x: None,
            })),
            network_settings: Some(NetworkSettings::WebSocket {
                path: "/trojan".to_string(),
                host: "example.com".to_string(),
            }),
            allow_insecure: false,
        }];

        let result = generate_outbounds(&servers);
        assert!(result.is_ok());

        let config = result.unwrap();
        let outbounds = config["outbounds"].as_array().unwrap();

        let trojan = &outbounds[0];
        assert_eq!(trojan["streamSettings"]["network"], "ws");
        assert_eq!(trojan["streamSettings"]["wsSettings"]["path"], "/trojan");
        assert_eq!(
            trojan["streamSettings"]["wsSettings"]["headers"]["Host"],
            "example.com"
        );
    }

    #[test]
    fn test_generate_outbounds_hysteria2() {
        let servers = vec![ServerConfig::Hysteria2 {
            tag: "hysteria2-server".to_string(),
            address: "example.com".to_string(),
            port: 443,
            password: "test-password".to_string(),
            server_name: "example.com".to_string(),
            allow_insecure: false,
            obfs: Some("salamander".to_string()),
            obfs_password: Some("obfs-pass".to_string()),
        }];

        let result = generate_outbounds(&servers);
        assert!(result.is_ok());

        let config = result.unwrap();
        let outbounds = config["outbounds"].as_array().unwrap();

        let hysteria = &outbounds[0];
        assert_eq!(hysteria["tag"], "hysteria2-server");
        assert_eq!(hysteria["protocol"], "hysteria");
        assert_eq!(hysteria["settings"]["auth"], "test-password");
        assert_eq!(hysteria["settings"]["server"], "example.com");
        assert_eq!(hysteria["settings"]["serverPort"], 443);
        assert_eq!(hysteria["settings"]["tls"]["serverName"], "example.com");
        assert_eq!(hysteria["settings"]["obfs"]["type"], "salamander");
        assert_eq!(hysteria["settings"]["obfs"]["password"], "obfs-pass");
    }
}
