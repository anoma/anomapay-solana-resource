#!/usr/bin/env bash
#
# Refuse to ship a change of a circuit's VK without a matching entry in its
# library's VK_HISTORY.md, for every library (`*_library`).
#
# Run from repo root:  ./scripts/check-vk-history.sh
#
# The check is deliberately simple — it does not look at git diffs or base
# refs, just confirms that whatever VK is currently in each library's lib.rs
# appears in its history file. That makes it robust to PR vs. push events, to
# merges, and to local runs. The author's commitment is the *entry*; CI just
# enforces that the entry exists.
set -euo pipefail

check_library() {
  local lib_rs="$1/src/lib.rs"
  local history="$1/VK_HISTORY.md"

  if [[ ! -f "$lib_rs" ]]; then
    echo "❌ $lib_rs not found. Run from repo root." >&2
    exit 1
  fi
  if [[ ! -f "$history" ]]; then
    echo "❌ $history not found." >&2
    exit 1
  fi

  # Extract the 64-hex VK literal: Digest::from_bytes(hex!("<64 hex chars>")).
  # The file must hold exactly one such literal, or the check cannot know
  # which one is the VK.
  local vks
  mapfile -t vks < <(grep -oE '"[0-9a-f]{64}"' "$lib_rs" | tr -d '"')
  if [[ ${#vks[@]} -ne 1 ]]; then
    echo "❌ Expected exactly one 64-hex VK literal in $lib_rs, found ${#vks[@]}." >&2
    echo "   Expected pattern: Digest::from_bytes(hex!(\"<64 hex chars>\"))" >&2
    exit 1
  fi
  local current_vk="${vks[0]}"

  # History entries embed the VK in backtick-fenced code spans:
  #     | `<64-hex>` | ... |
  if ! grep -qE "\`${current_vk}\`" "$history"; then
    echo "❌ The VK in $lib_rs does not appear in $history." >&2
    echo "" >&2
    echo "   Current VK: $current_vk" >&2
    echo "" >&2
    echo "   Every change to a circuit's VK orphans persistent shielded" >&2
    echo "   resources minted under the prior VK. Add an entry to" >&2
    echo "   $history documenting why this rotation is happening and how" >&2
    echo "   holders of pre-bump resources will spend or recover them." >&2
    echo "" >&2
    echo "   See the 'Process for adding a new VK' section at the bottom" >&2
    echo "   of transfer_library/VK_HISTORY.md for the expected format." >&2
    exit 1
  fi

  echo "✅ The VK in $lib_rs is documented in $history: $current_vk"
}

for library in *_library; do
  check_library "$library"
done
