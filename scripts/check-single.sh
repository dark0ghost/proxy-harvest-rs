#!/bin/bash
# check-single.sh - Тест одного конкретного прокси
# Usage: ./check-single.sh <tag> [config_dir] [timeout]

set -e

TAG="$1"
CONFIG_DIR="${2:-/app/configs}"
TIMEOUT="${3:-$TEST_TIMEOUT}"

OUTBOUNDS_FILE="$CONFIG_DIR/04_outbounds.json"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

if [[ -z "$TAG" ]]; then
    echo "Usage: $0 <tag> [config_dir] [timeout]"
    echo ""
    echo "Available tags:"
    jq -r '.outbounds[].tag' "$OUTBOUNDS_FILE" 2>/dev/null | head -20
    exit 1
fi

echo "========================================"
echo "  Testing Single Proxy: $TAG"
echo "========================================"
echo ""

# Find the proxy by tag
proxy=$(jq -c ".outbounds[] | select(.tag == \"$TAG\")" "$OUTBOUNDS_FILE")

if [[ -z "$proxy" ]]; then
    echo -e "${RED}✗${NC} Proxy with tag '$TAG' not found"
    echo ""
    echo "Available tags:"
    jq -r '.outbounds[].tag' "$OUTBOUNDS_FILE" 2>/dev/null
    exit 1
fi

# Extract proxy details
tag=$(echo "$proxy" | jq -r '.tag')
protocol=$(echo "$proxy" | jq -r '.protocol')
address=$(echo "$proxy" | jq -r '.settings.vnext[0].address // .settings.servers[0].address')
port=$(echo "$proxy" | jq -r '.settings.vnext[0].port // .settings.servers[0].port')
network=$(echo "$proxy" | jq -r '.streamSettings.network // "tcp"')
security=$(echo "$proxy" | jq -r '.streamSettings.security // "none"')

echo "Protocol:  $protocol"
echo "Address:   $address:$port"
echo "Network:   $network"
echo "Security:  $security"
echo ""

# Create client config
TEMP_DIR=$(mktemp -d)
trap "rm -rf $TEMP_DIR" EXIT

client_config="$TEMP_DIR/client.json"

# Get user credentials
if [[ "$protocol" == "vless" ]]; then
    user_id=$(echo "$proxy" | jq -r '.settings.vnext[0].users[0].id')
    flow=$(echo "$proxy" | jq -r '.settings.vnext[0].users[0].flow // ""')
elif [[ "$protocol" == "trojan" ]]; then
    user_id=$(echo "$proxy" | jq -r '.settings.servers[0].password')
elif [[ "$protocol" == "shadowsocks" ]]; then
    method=$(echo "$proxy" | jq -r '.settings.servers[0].method')
    password=$(echo "$proxy" | jq -r '.settings.servers[0].password')
    user_id="$method:$password"
fi

# Get stream settings
sni=$(echo "$proxy" | jq -r '.streamSettings.tlsSettings.serverName // .streamSettings.realitySettings.serverName // ""')
pbk=$(echo "$proxy" | jq -r '.streamSettings.realitySettings.publicKey // ""')
sid=$(echo "$proxy" | jq -r '.streamSettings.realitySettings.shortId // ""')
path=$(echo "$proxy" | jq -r '.streamSettings.wsSettings.path // .streamSettings.grpcSettings.serviceName // ""')
host=$(echo "$proxy" | jq -r '.streamSettings.wsSettings.host // ""')

# Build client config
cat > "$client_config" << EOF
{
  "inbounds": [{
    "port": 1080,
    "listen": "127.0.0.1",
    "protocol": "socks",
    "settings": {"auth": "noauth", "udp": false}
  }],
  "outbounds": [{
    "protocol": "$protocol",
    "tag": "proxy",
    "settings": {
EOF

if [[ "$protocol" == "vless" ]]; then
    cat >> "$client_config" << EOF
      "vnext": [{
        "address": "$address",
        "port": $port,
        "users": [{
          "id": "$user_id",
          "encryption": "none",
          "flow": "$flow"
        }]
      }]
EOF
elif [[ "$protocol" == "trojan" ]]; then
    cat >> "$client_config" << EOF
      "servers": [{
        "address": "$address",
        "port": $port,
        "password": "$user_id",
        "level": 0
      }]
EOF
elif [[ "$protocol" == "shadowsocks" ]]; then
    cat >> "$client_config" << EOF
      "servers": [{
        "address": "$address",
        "port": $port,
        "method": "$method",
        "password": "$password",
        "level": 0
      }]
EOF
fi

cat >> "$client_config" << EOF
    },
    "streamSettings": {
      "network": "$network",
      "security": "$security"
EOF

# Add TLS/Reality settings
if [[ "$security" == "tls" && -n "$sni" ]]; then
    cat >> "$client_config" << EOF
      ,
      "tlsSettings": {
        "serverName": "$sni",
        "allowInsecure": false,
        "fingerprint": "chrome"
      }
EOF
elif [[ "$security" == "reality" && -n "$pbk" ]]; then
    cat >> "$client_config" << EOF
      ,
      "realitySettings": {
        "serverName": "$sni",
        "fingerprint": "chrome",
        "publicKey": "$pbk",
        "shortId": "$sid"
      }
EOF
fi

# Add network-specific settings
if [[ "$network" == "ws" && -n "$path" ]]; then
    cat >> "$client_config" << EOF
      ,
      "wsSettings": {
        "path": "$path",
        "host": "$host"
      }
EOF
elif [[ "$network" == "grpc" ]]; then
    cat >> "$client_config" << EOF
      ,
      "grpcSettings": {
        "serviceName": "${path:-grpc}"
      }
EOF
fi

cat >> "$client_config" << EOF
    }
  }],
  "routing": {
    "domainStrategy": "AsIs"
  }
}
EOF

echo "Client config created: $client_config"
echo ""

# Validate config
echo "Validating config..."
if xray test -config "$client_config" 2>&1 | grep -q "config valid"; then
    echo -e "${GREEN}✓${NC} Config is valid"
else
    echo -e "${YELLOW}⚠${NC} Config validation skipped (xray test not available)"
fi
echo ""

# Start Xray
echo "Starting Xray..."
xray -config "$client_config" > "$TEMP_DIR/xray.log" 2>&1 &
xray_pid=$!

# Wait for Xray to start
sleep 2

# Check if Xray is running
if ! kill -0 $xray_pid 2>/dev/null; then
    echo -e "${RED}✗${NC} Xray failed to start"
    echo "Log:"
    cat "$TEMP_DIR/xray.log"
    exit 1
fi

echo -e "${GREEN}✓${NC} Xray started (PID: $xray_pid)"
echo ""

# Test connection
echo "Testing connection through proxy..."
echo ""

start_time=$(date +%s%3N)

# Get IP from ipify.org first
echo "Fetching IP from ipify.org..."
response=$(timeout "$TIMEOUT" curl -s -x "socks5://127.0.0.1:1080" \
    "https://api.ipify.org?format=json" \
    --connect-timeout 5 \
    --max-time "$TIMEOUT" \
    2>&1) || true

if echo "$response" | jq -e '.ip' > /dev/null 2>&1; then
    ip=$(echo "$response" | jq -r '.ip')
    
    # Get country info from ip-api.com
    echo "Fetching country info..."
    country_response=$(timeout "$TIMEOUT" curl -s \
        "http://ip-api.com/json/$ip?fields=country,countryCode,isp" \
        --connect-timeout 3 \
        --max-time 5 \
        2>&1) || true
    
    if echo "$country_response" | jq -e '.countryCode' > /dev/null 2>&1; then
        country=$(echo "$country_response" | jq -r '.country // "Unknown"')
        country_code=$(echo "$country_response" | jq -r '.countryCode // "XX"')
        isp=$(echo "$country_response" | jq -r '.isp // "Unknown"')
    else
        country="Unknown"
        country_code="XX"
        isp="Unknown"
    fi
    
    end_time=$(date +%s%3N)
    duration=$((end_time - start_time))
    
    echo ""
    echo "========================================"
    echo -e "  ${GREEN}✓ Proxy is working!${NC}"
    echo "========================================"
    echo ""
    echo "  IP:          $ip"
    echo "  Country:     $country ($country_code)"
    echo "  ISP:         $isp"
    echo "  Response:    ${duration}ms"
    echo ""
    
    # Test HTTPS
    echo "Testing HTTPS connectivity..."
    https_test=$(timeout "$TIMEOUT" curl -s -x "socks5://127.0.0.1:1080" \
        -I "https://www.google.com" \
        --connect-timeout 5 \
        --max-time "$TIMEOUT" \
        2>&1 | head -1) || true
    
    if [[ -n "$https_test" ]]; then
        echo -e "  ${GREEN}✓${NC} HTTPS: $https_test"
    else
        echo -e "  ${YELLOW}⚠${NC} HTTPS: No response"
    fi
    
    # Test HTTP
    echo "Testing HTTP connectivity..."
    http_test=$(timeout "$TIMEOUT" curl -s -x "socks5://127.0.0.1:1080" \
        -I "http://www.google.com" \
        --connect-timeout 5 \
        --max-time "$TIMEOUT" \
        2>&1 | head -1) || true
    
    if [[ -n "$http_test" ]]; then
        echo -e "  ${GREEN}✓${NC} HTTP: $http_test"
    else
        echo -e "  ${YELLOW}⚠${NC} HTTP: No response"
    fi
    
    echo ""
    echo "========================================"
    
    # Stop Xray
    kill $xray_pid 2>/dev/null || true
    exit 0
else
    end_time=$(date +%s%3N)
    duration=$((end_time - start_time))
    
    echo ""
    echo -e "${RED}✗${NC} Failed to get IP through proxy"
    echo "  Response time: ${duration}ms"
    echo ""
    echo "Raw response: $response"
    echo ""
    
    # Check Xray log
    echo "Xray log:"
    cat "$TEMP_DIR/xray.log"
    
    # Stop Xray
    kill $xray_pid 2>/dev/null || true
    exit 1
fi
