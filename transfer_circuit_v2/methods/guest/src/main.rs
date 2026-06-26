use risc0_zkvm::guest::env;
use transfer_witness_v2::{LogicCircuit, TokenTransferWitnessV2};

fn main() {
    let witness: TokenTransferWitnessV2 = env::read();
    let instance = witness.constrain().unwrap();
    env::commit(&instance);
}
