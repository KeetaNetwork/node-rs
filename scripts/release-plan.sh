#!/bin/bash
set -eo pipefail

# Usage: scripts/release-plan.sh [BASE_REF] [HEAD_REF]
#
# Prints, as GitHub Actions outputs:
#   mode=full     [workspace.package].version changed
#   mode=subset   only crate versions changed
#   mode=none     no version changed
#   packages=...  crates whose version changed

readonly PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

head_ref="${2:-HEAD}"
base_ref="${1:-}"

if [[ -z "$base_ref" || "$base_ref" =~ ^0+$ ]] || ! git cat-file -e "${base_ref}^{commit}" 2>/dev/null; then
    base_ref="${head_ref}^"
fi

# Keeps the old tree's rust-toolchain.toml from installing another toolchain.
RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-$(rustup show active-toolchain 2>/dev/null | cut -d' ' -f1)}"
export RUSTUP_TOOLCHAIN

workdir="$(mktemp -d)"
cleanup() {
    git worktree remove --force "$workdir/base" > /dev/null 2>&1 || true
    git worktree remove --force "$workdir/head" > /dev/null 2>&1 || true
    rm -rf "$workdir"
}
trap cleanup EXIT

tree_versions() {
    local ref="$1"
    local dir="$2"

    git worktree add --detach --quiet "$dir" "$ref"
    cargo metadata --no-deps --format-version 1 --manifest-path "$dir/Cargo.toml" \
        | jq -r '.packages[] | select(.publish != []) | "\(.name) \(.version)"' | sort
    echo "@workspace $(sed -n '/^\[workspace.package\]/,/^\[/{s/^version *= *"\(.*\)"/\1/p}' "$dir/Cargo.toml" | head -1)"
}

base_versions="$(tree_versions "$base_ref" "$workdir/base")"
head_versions="$(tree_versions "$head_ref" "$workdir/head")"

changed="$(comm -13 <(echo "$base_versions" | sort) <(echo "$head_versions" | sort))"

packages="$(echo "$changed" | awk '$1 != "@workspace" && NF { print $1 }' | tr '\n' ' ' | sed 's/ $//')"

if echo "$changed" | grep -q '^@workspace '; then
    mode=full
elif [[ -n "$packages" ]]; then
    mode=subset
else
    mode=none
fi

echo "Comparing $(git rev-parse --short "$base_ref")..$(git rev-parse --short "$head_ref")" >&2
if [[ -n "$changed" ]]; then
    echo "Version changes:" >&2
    echo "$changed" | sed 's/^/  /' >&2
fi

echo "mode=$mode"
echo "packages=$packages"
