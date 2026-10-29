# transfer_library

Host-side proving API for the AnomaPay Solana token-transfer resource.

## `TransferLogic`

Wraps a `TokenTransferWitness` and implements ARM's `LogicProver`, so
`logic.prove(proof_type)` produces a `LogicVerifier` for the resource. The
constructors build the witness for each supported flow:

| Constructor | Resource | Flow |
|---|---|---|
| `consume_persistent_resource_logic` | consumed persistent | spend a shielded resource (owner signature) |
| `create_persistent_resource_logic` | created persistent | mint a shielded resource (encrypted payload) |
| `mint_resource_logic_with_wrap_auth` | consumed ephemeral | wrap SPL tokens (Ed25519 authorization) |
| `burn_resource_logic` | created ephemeral | unwrap SPL tokens to a recipient |

## Actions

`action::wrap` and `action::unwrap` build a flow's resources from its keys and
terms: the ephemeral resource a wrap consumes and the owner's shielded resource
it creates, or the shielded resource an unwrap consumes and the ephemeral one it
creates for the recipient. Each flow is of a logic `L`, `TransferLogic` or a
logic that extends it (`wrap::<TransferLogic>(..)`): its resources carry
`L`'s verifying key and its witnesses are `L`'s. A wrap's resources are a
`Deposit`, the shape any call bringing a quantity into the shielded pool
shares. A created resource's nonce is set when its action is laid out.

An action is built in two steps. `Layout::new` takes the resources of one or
several flows (each flow's `resources()`, consumed then created) in the
caller's order, which is the order of the resources in the compliance
instance and of the forwarder calls. It derives each created resource's nonce
from its place among them and gives the laid-out resources, their tags and
the action tree root, which the owners and users sign, in process or not.
`Wrap::signed_message` is the text the user's wallet signs for that root.
Each flow's `logic_witnesses` makes its logic witnesses from its laid-out
created resource, the root and its signature, and `Layout::action` takes the
logic witnesses in the layout's order and returns a `TransferAction<L>`: the
compliance witness and the logic witnesses, which `TransferAction::prove`
proves in-process into a balanced transaction, or which a caller with its own
prover (a proving queue, a mock prover) proves itself.

`Wrap::action` and `Unwrap::action` do both steps for an action of that flow
alone, given the signature over its `layout()`'s root.

## Guest artifacts

`TOKEN_TRANSFER_ELF` is the prebuilt guest (`elf/token-transfer-guest.bin`) and
`TOKEN_TRANSFER_ID` its RISC0 image ID, the resource's logic reference. Every
change to the ID is recorded in [`VK_HISTORY.md`](VK_HISTORY.md); CI refuses an
ID that is not recorded there.

## Tests

`src/test.rs` proves each flow against the embedded guest. Run with
`RISC0_DEV_MODE=1` for fast, non-cryptographic proofs.
