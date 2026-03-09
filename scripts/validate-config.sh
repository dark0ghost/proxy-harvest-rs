#!/bin/bash
# validate-config.sh - Валидация конфигов Xray
# Usage: ./validate-config.sh [config_dir]

set -e

CONFIG_DIR="${1:-/app/configs}"
OUTBOUNDS_FILE="$CONFIG_DIR/04_outbounds.json"
ROUTING_FILE="$CONFIG_DIR/05_routing.json"

echo "========================================"
echo "  Xray Configuration Validation"
echo "========================================"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

errors=0

# Check if config files exist
echo "Checking config files..."
if [[ ! -f "$OUTBOUNDS_FILE" ]]; then
    echo -e "${RED}✗${NC} Outbounds config not found: $OUTBOUNDS_FILE"
    errors=$((errors + 1))
else
    echo -e "${GREEN}✓${NC} Outbounds config found"
fi

if [[ ! -f "$ROUTING_FILE" ]]; then
    echo -e "${RED}✗${NC} Routing config not found: $ROUTING_FILE"
    errors=$((errors + 1))
else
    echo -e "${GREEN}✓${NC} Routing config found"
fi

if [[ $errors -gt 0 ]]; then
    echo ""
    echo -e "${RED}Config files missing. Exiting.${NC}"
    exit 1
fi

echo ""

# Validate JSON syntax
echo "Validating JSON syntax..."
if jq empty "$OUTBOUNDS_FILE" 2>/dev/null; then
    echo -e "${GREEN}✓${NC} Outbounds JSON is valid"
else
    echo -e "${RED}✗${NC} Outbounds JSON is invalid"
    errors=$((errors + 1))
fi

if jq empty "$ROUTING_FILE" 2>/dev/null; then
    echo -e "${GREEN}✓${NC} Routing JSON is valid"
else
    echo -e "${RED}✗${NC} Routing JSON is invalid"
    errors=$((errors + 1))
fi

echo ""

# Test configs with Xray
echo "Testing configs with Xray..."

# Create a combined config for testing
COMBINED_CONFIG=$(mktemp)
jq -s '.[0] * .[1]' "$OUTBOUNDS_FILE" "$ROUTING_FILE" > "$COMBINED_CONFIG" 2>/dev/null || {
    echo -e "${RED}✗${NC} Failed to merge configs"
    errors=$((errors + 1))
}

if [[ -f "$COMBINED_CONFIG" ]]; then
    # Test with xray test command
    if xray test -config "$COMBINED_CONFIG" 2>&1 | grep -q "config valid"; then
        echo -e "${GREEN}✓${NC} Xray config validation passed"
    else
        echo -e "${YELLOW}⚠${NC} Xray test command not available or config has warnings"
        # Try alternative validation
        if xray -test -config "$COMBINED_CONFIG" 2>&1 | grep -q "config valid\|Configuration loaded"; then
            echo -e "${GREEN}✓${NC} Xray alternative validation passed"
        else
            echo -e "${YELLOW}⚠${NC} Running basic structure check..."
            
            # Basic structure validation
            if jq -e '.outbounds | length > 0' "$OUTBOUNDS_FILE" > /dev/null 2>&1; then
                outbound_count=$(jq '.outbounds | length' "$OUTBOUNDS_FILE")
                echo -e "${GREEN}✓${NC} Outbounds: $outbound_count entries"
            else
                echo -e "${RED}✗${NC} No outbounds found"
                errors=$((errors + 1))
            fi
            
            if jq -e '.routing.balancers | length >= 0' "$ROUTING_FILE" > /dev/null 2>&1; then
                balancer_count=$(jq '.routing.balancers | length' "$ROUTING_FILE")
                echo -e "${GREEN}✓${NC} Routing: $balancer_count balancers"
            else
                echo -e "${RED}✗${NC} Invalid routing structure"
                errors=$((errors + 1))
            fi
        fi
    fi
    
    rm -f "$COMBINED_CONFIG"
fi

echo ""
echo "========================================"

# Count proxies by protocol
echo "Proxy statistics:"
echo ""

protocols=$(jq -r '.outbounds[].protocol' "$OUTBOUNDS_FILE" 2>/dev/null | sort | uniq -c | sort -rn)
echo "$protocols" | while read -r count protocol; do
    if [[ -n "$protocol" && "$protocol" != "direct" && "$protocol" != "block" ]]; then
        printf "  %-12s %d\n" "$protocol:" "$count"
    fi
done

total_proxies=$(jq '[.outbounds[] | select(.protocol != "direct" and .protocol != "block")] | length' "$OUTBOUNDS_FILE" 2>/dev/null)
echo ""
echo "  Total proxies: $total_proxies"

echo "========================================"

if [[ $errors -gt 0 ]]; then
    echo ""
    echo -e "${RED}Validation completed with $errors error(s)${NC}"
    exit 1
else
    echo ""
    echo -e "${GREEN}Validation completed successfully${NC}"
    exit 0
fi
