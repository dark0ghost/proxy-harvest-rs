#!/bin/bash
# test-proxies.sh - Тестирование работоспособности прокси
# Usage: ./test-proxies.sh [config_dir] [timeout] [parallel]

set -e

CONFIG_DIR="${1:-/app/configs}"
TIMEOUT="${2:-$TEST_TIMEOUT}"
PARALLEL="${3:-$PARALLEL_TESTS}"
OUTPUT_FORMAT="${OUTPUT_FORMAT:-text}"

OUTBOUNDS_FILE="$CONFIG_DIR/04_outbounds.json"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Counters
total=0
working=0
failed=0
declare -A country_stats
declare -A country_total

# Temporary files for parallel processing
TEMP_DIR=$(mktemp -d)
trap "rm -rf $TEMP_DIR" EXIT

# Country code to emoji mapping
declare -A country_emoji=(
    ["AD"]="🇦🇩" ["AE"]="🇦🇪" ["AF"]="🇦🇫" ["AG"]="🇦🇬" ["AI"]="🇦🇮"
    ["AL"]="🇦🇱" ["AM"]="🇦🇲" ["AO"]="🇦🇴" ["AQ"]="🇦🇶" ["AR"]="🇦🇷"
    ["AS"]="🇦🇸" ["AT"]="🇦🇹" ["AU"]="🇦🇺" ["AW"]="🇦🇼" ["AX"]="🇦🇽"
    ["AZ"]="🇦🇿" ["BA"]="🇧🇦" ["BB"]="🇧🇧" ["BD"]="🇧🇩" ["BE"]="🇧🇪"
    ["BF"]="🇧🇫" ["BG"]="🇧🇬" ["BH"]="🇧🇭" ["BI"]="🇧🇮" ["BJ"]="🇧🇯"
    ["BL"]="🇧🇱" ["BM"]="🇧🇲" ["BN"]="🇧🇳" ["BO"]="🇧🇴" ["BQ"]="🇧🇶"
    ["BR"]="🇧🇷" ["BS"]="🇧🇸" ["BT"]="🇧🇹" ["BV"]="🇧🇻" ["BW"]="🇧🇼"
    ["BY"]="🇧🇾" ["BZ"]="🇧🇿" ["CA"]="🇨🇦" ["CC"]="🇨🇨" ["CD"]="🇨🇩"
    ["CF"]="🇨🇫" ["CG"]="🇨🇬" ["CH"]="🇨🇭" ["CI"]="🇨🇮" ["CK"]="🇨🇰"
    ["CL"]="🇨🇱" ["CM"]="🇨🇲" ["CN"]="🇨🇳" ["CO"]="🇨🇴" ["CR"]="🇨🇷"
    ["CU"]="🇨🇺" ["CV"]="🇨🇻" ["CW"]="🇨🇼" ["CX"]="🇨🇽" ["CY"]="🇨🇾"
    ["CZ"]="🇨🇿" ["DE"]="🇩🇪" ["DJ"]="🇩🇯" ["DK"]="🇩🇰" ["DM"]="🇩🇲"
    ["DO"]="🇩🇴" ["DZ"]="🇩🇿" ["EC"]="🇪🇨" ["EE"]="🇪🇪" ["EG"]="🇪🇬"
    ["EH"]="🇪🇭" ["ER"]="🇪🇷" ["ES"]="🇪🇸" ["ET"]="🇪🇹" ["FI"]="🇫🇮"
    ["FJ"]="🇫🇯" ["FK"]="🇫🇰" ["FM"]="🇫🇲" ["FO"]="🇫🇴" ["FR"]="🇫🇷"
    ["GA"]="🇬🇦" ["GB"]="🇬🇧" ["GD"]="🇬🇩" ["GE"]="🇬🇪" ["GF"]="🇬🇫"
    ["GG"]="🇬🇬" ["GH"]="🇬🇭" ["GI"]="🇬🇮" ["GL"]="🇬🇱" ["GM"]="🇬🇲"
    ["GN"]="🇬🇳" ["GP"]="🇬🇵" ["GQ"]="🇬🇶" ["GR"]="🇬🇷" ["GS"]="🇬🇸"
    ["GT"]="🇬🇹" ["GU"]="🇬🇺" ["GW"]="🇬🇼" ["GY"]="🇬🇾" ["HK"]="🇭🇰"
    ["HM"]="🇭🇲" ["HN"]="🇭🇳" ["HR"]="🇭🇷" ["HT"]="🇭🇹" ["HU"]="🇭🇺"
    ["ID"]="🇮🇩" ["IE"]="🇮🇪" ["IL"]="🇮🇱" ["IM"]="🇮🇲" ["IN"]="🇮🇳"
    ["IO"]="🇮🇴" ["IQ"]="🇮🇶" ["IR"]="🇮🇷" ["IS"]="🇮🇸" ["IT"]="🇮🇹"
    ["JE"]="🇯🇪" ["JM"]="🇯🇲" ["JO"]="🇯🇴" ["JP"]="🇯🇵" ["KE"]="🇰🇪"
    ["KG"]="🇰🇬" ["KH"]="🇰🇭" ["KI"]="🇰🇮" ["KM"]="🇰🇲" ["KN"]="🇰🇳"
    ["KP"]="🇰🇵" ["KR"]="🇰🇷" ["KW"]="🇰🇼" ["KY"]="🇰🇾" ["KZ"]="🇰🇿"
    ["LA"]="🇱🇦" ["LB"]="🇱🇧" ["LC"]="🇱🇨" ["LI"]="🇱🇮" ["LK"]="🇱🇰"
    ["LR"]="🇱🇷" ["LS"]="🇱🇸" ["LT"]="🇱🇹" ["LU"]="🇱🇺" ["LV"]="🇱🇻"
    ["LY"]="🇱🇾" ["MA"]="🇲🇦" ["MC"]="🇲🇨" ["MD"]="🇲🇩" ["ME"]="🇲🇪"
    ["MF"]="🇲🇫" ["MG"]="🇲🇬" ["MH"]="🇲🇭" ["MK"]="🇲🇰" ["ML"]="🇲🇱"
    ["MM"]="🇲🇲" ["MN"]="🇲🇳" ["MO"]="🇲🇴" ["MP"]="🇲🇵" ["MQ"]="🇲🇶"
    ["MR"]="🇲🇷" ["MS"]="🇲🇸" ["MT"]="🇲🇹" ["MU"]="🇲🇺" ["MV"]="🇲🇻"
    ["MW"]="🇲🇼" ["MX"]="🇲🇽" ["MY"]="🇲🇾" ["MZ"]="🇲🇿" ["NA"]="🇳🇦"
    ["NC"]="🇳🇨" ["NE"]="🇳🇪" ["NF"]="🇳🇫" ["NG"]="🇳🇬" ["NI"]="🇳🇮"
    ["NL"]="🇳🇱" ["NO"]="🇳🇴" ["NP"]="🇳🇵" ["NR"]="🇳🇷" ["NU"]="🇳🇺"
    ["NZ"]="🇳🇿" ["OM"]="🇴🇲" ["PA"]="🇵🇦" ["PE"]="🇵🇪" ["PF"]="🇵🇫"
    ["PG"]="🇵🇬" ["PH"]="🇵🇭" ["PK"]="🇵🇰" ["PL"]="🇵🇱" ["PM"]="🇵🇲"
    ["PN"]="🇵🇳" ["PR"]="🇵🇷" ["PS"]="🇵🇸" ["PT"]="🇵🇹" ["PW"]="🇵🇼"
    ["PY"]="🇵🇾" ["QA"]="🇶🇦" ["RE"]="🇷🇪" ["RO"]="🇷🇴" ["RS"]="🇷🇸"
    ["RU"]="🇷🇺" ["RW"]="🇷🇼" ["SA"]="🇸🇦" ["SB"]="🇸🇧" ["SC"]="🇸🇨"
    ["SD"]="🇸🇩" ["SE"]="🇸🇪" ["SG"]="🇸🇬" ["SH"]="🇸🇭" ["SI"]="🇸🇮"
    ["SJ"]="🇸🇯" ["SK"]="🇸🇰" ["SL"]="🇸🇱" ["SM"]="🇸🇲" ["SN"]="🇸🇳"
    ["SO"]="🇸🇴" ["SR"]="🇸🇷" ["SS"]="🇸🇸" ["ST"]="🇸🇹" ["SV"]="🇸🇻"
    ["SX"]="🇸🇽" ["SY"]="🇸🇾" ["SZ"]="🇸🇿" ["TC"]="🇹🇨" ["TD"]="🇹🇩"
    ["TF"]="🇹🇫" ["TG"]="🇹🇬" ["TH"]="🇹🇭" ["TJ"]="🇹🇯" ["TK"]="🇹🇰"
    ["TL"]="🇹🇱" ["TM"]="🇹🇲" ["TN"]="🇹🇳" ["TO"]="🇹🇴" ["TR"]="🇹🇷"
    ["TT"]="🇹🇹" ["TV"]="🇹🇻" ["TW"]="🇹🇼" ["TZ"]="🇹🇿" ["UA"]="🇺🇦"
    ["UG"]="🇺🇬" ["UM"]="🇺🇲" ["US"]="🇺🇸" ["UY"]="🇺🇾" ["UZ"]="🇺🇿"
    ["VA"]="🇻🇦" ["VC"]="🇻🇨" ["VE"]="🇻🇪" ["VG"]="🇻🇬" ["VI"]="🇻🇮"
    ["VN"]="🇻🇳" ["VU"]="🇻🇺" ["WF"]="🇼🇫" ["WS"]="🇼🇸" ["YE"]="🇾🇪"
    ["YT"]="🇾🇹" ["ZA"]="🇿🇦" ["ZM"]="🇿🇲" ["ZW"]="🇿🇼"
)

get_emoji() {
    local code="$1"
    echo "${country_emoji[$code]:-🌍}"
}

# Function to test a single proxy
test_proxy() {
    local index="$1"
    local tag="$2"
    local protocol="$3"
    local address="$4"
    local port="$5"
    local user_id="$6"
    local flow="$7"
    local network="$8"
    local security="$9"
    local sni="${10}"
    local pbk="${11}"
    local sid="${12}"
    local path="${13}"
    local host="${14}"
    
    local result_file="$TEMP_DIR/result_$index.json"
    local client_config="$TEMP_DIR/client_$index.json"
    local xray_pid=""
    local start_time=$(date +%s%3N)
    
    # Create client config with socks5 inbound
    cat > "$client_config" << EOF
{
  "inbounds": [{
    "port": $((1080 + index)),
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
        # For shadowsocks, user_id contains method:password
        local method=$(echo "$user_id" | cut -d: -f1)
        local password=$(echo "$user_id" | cut -d: -f2-)
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

    # Start Xray
    xray -config "$client_config" > "$TEMP_DIR/xray_$index.log" 2>&1 &
    xray_pid=$!
    
    # Wait for Xray to start
    sleep 1
    
    # Check if Xray is running
    if ! kill -0 $xray_pid 2>/dev/null; then
        local end_time=$(date +%s%3N)
        local duration=$((end_time - start_time))
        echo "{\"index\":$index,\"tag\":\"$tag\",\"status\":\"failed\",\"error\":\"Xray failed to start\",\"duration\":$duration}" > "$result_file"
        return 1
    fi
    
    # Test connection through proxy
    local proxy_port=$((1080 + index))
    local response
    local ip=""
    local country_code=""
    local error=""

    # First get IP from ipify.org
    response=$(timeout "$TIMEOUT" curl -s -x "socks5://127.0.0.1:$proxy_port" \
        "https://api.ipify.org?format=json" \
        --connect-timeout 5 \
        --max-time "$TIMEOUT" \
        2>&1) || true
    
    if echo "$response" | jq -e '.ip' > /dev/null 2>&1; then
        ip=$(echo "$response" | jq -r '.ip')
        
        # Then get country info from ip-api.com (using the IP we got)
        country_response=$(timeout "$TIMEOUT" curl -s \
            "http://ip-api.com/json/$ip?fields=countryCode" \
            --connect-timeout 3 \
            --max-time 5 \
            2>&1) || true
        
        if echo "$country_response" | jq -e '.countryCode' > /dev/null 2>&1; then
            country_code=$(echo "$country_response" | jq -r '.countryCode // "XX"')
        else
            country_code="XX"
        fi
    else
        # Fallback: try ipapi.co
        response=$(timeout "$TIMEOUT" curl -s -x "socks5://127.0.0.1:$proxy_port" \
            "http://ipapi.co/json/" \
            -H "User-Agent: Mozilla/5.0" \
            --connect-timeout 5 \
            --max-time "$TIMEOUT" \
            2>&1) || true
        
        if echo "$response" | jq -e '.ip' > /dev/null 2>&1; then
            ip=$(echo "$response" | jq -r '.ip')
            country_code=$(echo "$response" | jq -r '.country_code // "XX"')
        else
            error="Failed to get IP through proxy"
        fi
    fi
    
    # Stop Xray
    kill $xray_pid 2>/dev/null || true
    wait $xray_pid 2>/dev/null || true
    
    local end_time=$(date +%s%3N)
    local duration=$((end_time - start_time))
    
    if [[ -n "$ip" ]]; then
        echo "{\"index\":$index,\"tag\":\"$tag\",\"status\":\"ok\",\"ip\":\"$ip\",\"country_code\":\"$country_code\",\"duration\":$duration}" > "$result_file"
        return 0
    else
        echo "{\"index\":$index,\"tag\":\"$tag\",\"status\":\"failed\",\"error\":\"$error\",\"duration\":$duration}" > "$result_file"
        return 1
    fi
}

# Export function for parallel use
export -f test_proxy
export RED GREEN YELLOW BLUE CYAN NC
export TEMP_DIR TIMEOUT

# Main execution
echo "========================================"
echo "  Proxy Connectivity Test"
echo "========================================"
echo ""
echo "Config: $OUTBOUNDS_FILE"
echo "Timeout: ${TIMEOUT}s per proxy"
echo "Parallel tests: $PARALLEL"
echo ""

# Check if config exists
if [[ ! -f "$OUTBOUNDS_FILE" ]]; then
    echo -e "${RED}✗${NC} Config file not found: $OUTBOUNDS_FILE"
    exit 1
fi

# Get all outbounds (excluding direct and block)
mapfile -t proxies < <(jq -c '.outbounds[] | select(.protocol != "direct" and .protocol != "block")' "$OUTBOUNDS_FILE")

total=${#proxies[@]}
echo "Testing $total proxies..."
echo ""

# Process proxies in batches
current_batch=0
processed=0

for i in "${!proxies[@]}"; do
    proxy="${proxies[$i]}"
    
    # Extract proxy details
    tag=$(echo "$proxy" | jq -r '.tag')
    protocol=$(echo "$proxy" | jq -r '.protocol')
    
    # Get connection details based on protocol
    if [[ "$protocol" == "vless" ]]; then
        address=$(echo "$proxy" | jq -r '.settings.vnext[0].address')
        port=$(echo "$proxy" | jq -r '.settings.vnext[0].port')
        user_id=$(echo "$proxy" | jq -r '.settings.vnext[0].users[0].id')
        flow=$(echo "$proxy" | jq -r '.settings.vnext[0].users[0].flow // ""')
    elif [[ "$protocol" == "trojan" ]]; then
        address=$(echo "$proxy" | jq -r '.settings.servers[0].address')
        port=$(echo "$proxy" | jq -r '.settings.servers[0].port')
        user_id=$(echo "$proxy" | jq -r '.settings.servers[0].password')
        flow=""
    elif [[ "$protocol" == "shadowsocks" ]]; then
        address=$(echo "$proxy" | jq -r '.settings.servers[0].address')
        port=$(echo "$proxy" | jq -r '.settings.servers[0].port')
        method=$(echo "$proxy" | jq -r '.settings.servers[0].method')
        password=$(echo "$proxy" | jq -r '.settings.servers[0].password')
        user_id="$method:$password"
        flow=""
    else
        continue
    fi
    
    # Get stream settings
    network=$(echo "$proxy" | jq -r '.streamSettings.network // "tcp"')
    security=$(echo "$proxy" | jq -r '.streamSettings.security // "none"')
    sni=$(echo "$proxy" | jq -r '.streamSettings.tlsSettings.serverName // .streamSettings.realitySettings.serverName // ""')
    pbk=$(echo "$proxy" | jq -r '.streamSettings.realitySettings.publicKey // ""')
    sid=$(echo "$proxy" | jq -r '.streamSettings.realitySettings.shortId // ""')
    path=$(echo "$proxy" | jq -r '.streamSettings.wsSettings.path // .streamSettings.grpcSettings.serviceName // ""')
    host=$(echo "$proxy" | jq -r '.streamSettings.wsSettings.host // ""')
    
    # Print progress
    printf "${CYAN}[%3d/%3d]${NC} Testing %-30s (%s:%s) ... " $((i + 1)) "$total" "$tag" "$address" "$port"
    
    # Run test
    if test_proxy "$i" "$tag" "$protocol" "$address" "$port" "$user_id" "$flow" "$network" "$security" "$sni" "$pbk" "$sid" "$path" "$host"; then
        result=$(cat "$TEMP_DIR/result_$i.json")
        status=$(echo "$result" | jq -r '.status')
        ip=$(echo "$result" | jq -r '.ip // "unknown"')
        country_code=$(echo "$result" | jq -r '.country_code // "XX"')
        duration=$(echo "$result" | jq -r '.duration')

        if [[ "$status" == "ok" ]]; then
            emoji=$(get_emoji "$country_code")
            printf "${GREEN}✓${NC} ${emoji} %-2s %-10s (%dms)\n" "$country_code" "$ip" "$duration"
            working=$((working + 1))
            country_stats["$country_code"]=$((${country_stats["$country_code"]:-0} + 1))
        else
            printf "${RED}✗${NC} Failed\n"
            failed=$((failed + 1))
        fi
    else
        result=$(cat "$TEMP_DIR/result_$i.json" 2>/dev/null || echo "{}")
        error=$(echo "$result" | jq -r '.error // "Unknown error"')
        duration=$(echo "$result" | jq -r '.duration // 0')
        printf "${RED}✗${NC} %s (%dms)\n" "$error" "$duration"
        failed=$((failed + 1))
        country_code="XX"
    fi

    country_total["$country_code"]=$((${country_total["$country_code"]:-0} + 1))
done

# Print summary
echo ""
echo "========================================"
echo "  Test Summary"
echo "========================================"
echo ""

success_rate=0
if [[ $total -gt 0 ]]; then
    success_rate=$((working * 100 / total))
fi

echo "  Total proxies:  $total"
echo "  Working:        ${GREEN}$working ($success_rate%)${NC}"
echo "  Failed:         ${RED}$failed${NC}"
echo ""

if [[ ${#country_stats[@]} -gt 0 ]]; then
    echo "  By country:"
    for country in "${!country_stats[@]}"; do
        if [[ -n "$country" && "$country" != "XX" && "$country" != "null" ]]; then
            emoji=$(get_emoji "$country")
            total_c=${country_total[$country]:-0}
            working_c=${country_stats[$country]:-0}
            printf "    %s %-4s %d/%d\n" "$emoji" "$country" "$working_c" "$total_c"
        fi
    done | sort -t'/' -k2 -rn
fi

echo ""
echo "========================================"

# JSON output if requested
if [[ "$OUTPUT_FORMAT" == "json" ]]; then
    echo ""
    echo "{"
    echo "  \"total\": $total,"
    echo "  \"working\": $working,"
    echo "  \"failed\": $failed,"
    echo "  \"success_rate\": $success_rate,"
    echo "  \"results\": ["
    
    first=true
    for i in "${!proxies[@]}"; do
        if [[ -f "$TEMP_DIR/result_$i.json" ]]; then
            if [[ "$first" == "true" ]]; then
                first=false
            else
                echo ","
            fi
            cat "$TEMP_DIR/result_$i.json" | jq -c '.'
        fi
    done
    
    echo ""
    echo "  ]"
    echo "}"
fi

# Exit with error if any tests failed
if [[ $failed -gt 0 ]]; then
    exit 1
fi

exit 0
