#!/usr/bin/env bash
#
# Refuse to ship a TOKEN_TRANSFER_ID change without a matching entry in
# transfer_library/VK_HISTORY.md.
#
# Run from repo root:  ./scripts/check-vk-history.sh
#
# The check is deliberately simple — it does not look at git diffs or base
# refs, just confirms that whatever VK is currently in lib.rs appears in
# the history file. That makes it robust to PR vs. push events, to merges,
# and to local runs. The author's commitment is the *entry*; CI just
# enforces that the entry exists.
set -euo pipefail

LIB_RS="transfer_library/src/lib.rs"
HISTORY="transfer_library/VK_HISTORY.md"

if [[ ! -f "$LIB_RS" ]]; then
  echo "❌ $LIB_RS not found. Run from repo root." >&2
  exit 1
fi
if [[ ! -f "$HISTORY" ]]; then
  echo "❌ $HISTORY not found." >&2
  exit 1
fi

# Extract the 64-hex VK passed to Digest::from_hex(...) on the TOKEN_TRANSFER_ID
# line. The line we expect looks like:
#     Digest::from_hex("5a033ade...768f6")
current_vk="$(grep -oE '"[0-9a-f]{64}"' "$LIB_RS" | head -1 | tr -d '"')"
if [[ -z "$current_vk" ]]; then
  echo "❌ Could not find a 64-hex VK literal in $LIB_RS." >&2
  echo "   Expected pattern: Digest::from_hex(\"<64 hex chars>\")" >&2
  exit 1
fi

# History entries embed the VK in backtick-fenced code spans:
#     | `<64-hex>` | ... |
if ! grep -qE "\`${current_vk}\`" "$HISTORY"; then
  echo "❌ TOKEN_TRANSFER_ID in $LIB_RS does not appear in $HISTORY." >&2
  echo "" >&2
  echo "   Current VK: $current_vk" >&2
  echo "" >&2
  echo "   Every change to TOKEN_TRANSFER_ID orphans persistent shielded" >&2
  echo "   resources minted under the prior VK. Add an entry to" >&2
  echo "   $HISTORY documenting why this rotation is happening and how" >&2
  echo "   holders of pre-bump resources will spend or recover them." >&2
  echo "" >&2
  echo "   See the 'Process for adding a new VK' section at the bottom" >&2
  echo "   of $HISTORY for the expected format." >&2
  exit 1
fi

echo "✅ TOKEN_TRANSFER_ID is documented in $HISTORY: $current_vk"
