#!/usr/bin/env bash
#
# Build the GuardMGR agent as a fully STATIC Linux x86_64 binary.
#
# CGO_ENABLED=0 removes the glibc dependency and uses Go's pure DNS resolver, so
# the binary runs on any Linux x86_64 regardless of the build host's glibc. Do
# not drop CGO_ENABLED=0 — a dynamic build ties the binary to the build box.
#
#   ./build.sh 0.2.0
#
set -euo pipefail
VER="${1:-$(cat VERSION 2>/dev/null || echo dev)}"
mkdir -p bin
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath \
    -ldflags "-s -w -X main.version=${VER}" -o bin/guard-agent ./cmd/agent
file bin/guard-agent | grep -q 'statically linked' || { echo "!! build is not static"; exit 1; }
echo "built static guard-agent ${VER}: $(ls -la bin/guard-agent | awk '{print $5}') bytes"
