use emergency_migrating_transfer_witness::{EmergencyMigratingTokenTransferWitness, LogicCircuit};
use risc0_zkvm::guest::env;

fn main() {
    let witness: EmergencyMigratingTokenTransferWitness = env::read();
    let instance = witness.constrain().unwrap();
    env::commit(&instance);
}
