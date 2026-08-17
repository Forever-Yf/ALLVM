#!/usr/bin/env bash
set -euo pipefail

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

mkdir -p "$TMP_DIR/app/src/main/cpp"
touch "$TMP_DIR/settings.gradle"
touch "$TMP_DIR/build.gradle"
touch "$TMP_DIR/app/src/main/cpp/CMakeLists.txt"

python3 tools/allvm_android_command.py "$TMP_DIR" --json > /tmp/allvm-android-plan.json
grep -q 'gradle' /tmp/allvm-android-plan.json
grep -q 'cmake' /tmp/allvm-android-plan.json
