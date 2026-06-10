use risc0_zkvm::guest::env;
use transfer_witness::{LogicCircuit, TokenTransferWitness};

fn main() {
    let witness: TokenTransferWitness = env::read();
    let instance = witness.constrain().unwrap();
    env::commit(&instance);
}
