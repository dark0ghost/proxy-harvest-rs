# Docker build test script
set -e

echo "Building Docker image..."
docker build -t xray-config-gen:test .

echo ""
echo "Testing help command..."
docker run --rm xray-config-gen:test --help

echo ""
echo "Testing config generation..."
docker run --rm \
  -v "$(pwd)/test-output:/app/configs" \
  xray-config-gen:test \
  --url "https://raw.githubusercontent.com/STR97/STRUGOV/refs/heads/main/STR.BYPASS" \
  --output /app/configs

echo ""
echo "Generated files:"
ls -lh test-output/

echo ""
echo "✅ Docker build and test successful!"
