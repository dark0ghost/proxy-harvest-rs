#!/bin/bash
# entrypoint.sh - Главная точка входа для Docker образа
# Usage: docker run proxy-harvest-rs:test [command] [options]

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

show_help() {
    cat << EOF
${CYAN}Proxy Harvest RS - Xray Config Tester${NC}

${YELLOW}Usage:${NC}
  docker run -v \$(pwd)/configs:/app/configs proxy-harvest-rs:test [command] [options]

${YELLOW}Commands:${NC}
  all              Run full test suite (validate + test all proxies)
  validate         Only validate config files
  test             Test all proxies for connectivity
  single <tag>     Test a single proxy by tag
  generate         Generate configs from URL (requires TEST_URL)
  help             Show this help message

${YELLOW}Environment Variables:${NC}
  TEST_URL         URL to fetch server list from
  TEST_TIMEOUT     Timeout per proxy test (default: 10s)
  PARALLEL_TESTS   Number of parallel tests (default: 5)
  OUTPUT_FORMAT    Output format: text or json (default: text)
  XRAY_LOG_LEVEL   Xray log level (default: info)

${YELLOW}Examples:${NC}
  # Test existing configs
  docker run -v \$(pwd)/configs:/app/configs proxy-harvest-rs:test all

  # Only validate configs
  docker run -v \$(pwd)/configs:/app/configs proxy-harvest-rs:test validate

  # Generate and test configs
  docker run -v \$(pwd)/configs:/app/configs \\
    -e TEST_URL="https://example.com/servers.txt" \\
    proxy-harvest-rs:test all

  # Test single proxy
  docker run -v \$(pwd)/configs:/app/configs \\
    proxy-harvest-rs:test single vp1596--pol--vk-d837

  # JSON output for CI/CD
  docker run -v \$(pwd)/configs:/app/configs \\
    -e OUTPUT_FORMAT=json \\
    proxy-harvest-rs:test test > results.json

EOF
}

# Parse command
COMMAND="${1:-help}"
shift || true

case "$COMMAND" in
    validate)
        /app/scripts/validate-config.sh "$@"
        ;;
    test)
        /app/scripts/test-proxies.sh "$@"
        ;;
    single)
        /app/scripts/check-single.sh "$@"
        ;;
    generate)
        if [[ -z "$TEST_URL" ]]; then
            echo -e "${RED}✗${NC} TEST_URL environment variable is required"
            exit 1
        fi
        echo "Generating configs from $TEST_URL..."
        xray-config-gen --url "$TEST_URL" --output /app/configs
        ;;
    all)
        echo "========================================"
        echo "  Full Test Suite"
        echo "========================================"
        echo ""
        
        # Generate configs if TEST_URL is provided
        if [[ -n "$TEST_URL" ]]; then
            echo "Step 1: Generating configs..."
            echo ""
            xray-config-gen --url "$TEST_URL" --output /app/configs
            echo ""
        fi
        
        # Validate configs
        echo "Step 2: Validating configs..."
        echo ""
        /app/scripts/validate-config.sh || {
            echo -e "${RED}✗${NC} Config validation failed"
            exit 1
        }
        echo ""
        
        # Test proxies
        echo "Step 3: Testing proxies..."
        echo ""
        /app/scripts/test-proxies.sh || {
            echo -e "${YELLOW}⚠${NC} Some proxies failed"
        }
        ;;
    help|--help|-h)
        show_help
        ;;
    *)
        echo -e "${RED}✗${NC} Unknown command: $COMMAND"
        echo ""
        show_help
        exit 1
        ;;
esac
