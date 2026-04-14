#!/usr/bin/env bash
set -e

output=$(nix build .#yubikey-notifier 2>&1 || true)
expected=$(echo "$output" | grep "got:" | awk '{print $NF}')

if [[ -n "$expected" ]]; then
  sed -i "s|vendorHash = \".*\"|vendorHash = \"$expected\"|" flake.nix
  git add flake.nix
  echo "vendorHash updated to $expected — please amend your commit"
  exit 1
fi
