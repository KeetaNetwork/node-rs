#!/bin/bash
set -eo pipefail

# Decide what a push to main should release by comparing workspace crate
# versions between two commits.
#
# Usage: scripts/release-plan.sh [BASE_REF] [HEAD_REF]
#   BASE_REF defaults to HEAD^, HEAD_REF to HEAD. An unknown or all-zero
#   BASE_REF (first push, force push) falls back to HEAD_REF^.
#
# Prints GitHub Actions style key=value lines on stdout:
#   mode=none     no crate version changed
#   mode=full     [workspace.package].version changed: full release + tag
#   mode=subset   only crate versions changed: publish those crates, no tag
#   packages=...  space-separated crates whose version changed

readonly PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

head_ref="${2:-HEAD}"
base_ref="${1:-}"

if [[ -z "$base_ref" || "$base_ref" =~ ^0+$ ]] || ! git cat-file -e "${base_ref}^{commit}" 2>/dev/null; then
    base_ref="${head_ref}^"
fi

# Pin the toolchain so reading the old tree never triggers a toolchain
# install from its rust-toolchain.toml.
RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-$(rustup show active-toolchain 2>/dev/null | cut -d' ' -f1)}"
export RUSTUP_TOOLCHAIN

workdir="$(mktemp -d)"
cleanup() {
    git worktree remove --force "$workdir/base" > /dev/null 2>&1 || true
    git worktree remove --force "$workdir/head" > /dev/null 2>&1 || true
    rm -rf "$workdir"
}
trap cleanup EXIT

# Print "<crate> <version>" for every workspace member, plus the workspace
# version as "@workspace <version>", for the tree at the given ref.
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

# Lines present at HEAD but not at base: new crates or new versions.
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
