#!/bin/bash
set -e

# SMCP Security Framework Docker Entrypoint

echo "🚀 Starting SMCP Security Framework..."

# Set default configuration if not provided
if [ ! -f "/app/config.json" ]; then
    echo "📝 Creating default configuration..."
    python -m smcp_security.cli --init --config /app/config.json
fi

# Run system check
echo "🔍 Running system check..."
python -m smcp_security.cli --check-system

if [ $? -ne 0 ]; then
    echo "❌ System check failed"
    exit 1
fi

# Run self-test
echo "🧪 Running self-test..."
python -m smcp_security.cli --self-test --config /app/config.json

if [ $? -ne 0 ]; then
    echo "❌ Self-test failed"
    exit 1
fi

echo "✅ SMCP Security Framework ready"

# Execute the main command
exec python -m smcp_security.cli "$@" --config /app/config.json
