// Run this test with:
// cargo test --test test_proof -- --nocapture

use anyhow::Result;
use ark_ff::Zero;
use base64::{engine::general_purpose, Engine as _};
use ledger::{
    proofs::{
        prover::make_padded_proof_from_p2p,
        verification::{
            compute_deferred_values, get_message_for_next_step_proof,
            get_message_for_next_wrap_proof, get_prepared_statement, run_checks, verify_with, VK,
        },
        verifiers::make_zkapp_verifier_index,
    },
    VerificationKey,
};
use mina_curves::pasta::Fq;
use mina_p2p_messages::v2::{
    MinaBaseVerificationKeyWireStableV1, PicklesProofProofsVerified2ReprStableV2,
};
use verification_test::parse_o1js_proof_json;

#[test]
fn test_deserialize_o1js_proof() {
    let proof_json_str = include_str!("proof.json");
    let vk_b64 = include_str!("vk.txt");

    // Parse the o1js JSON proof
    let parsed = parse_o1js_proof_json(proof_json_str).expect("parse o1js proof JSON");

    eprintln!("public_input: {:?}", parsed.public_input);
    eprintln!("public_output: {:?}", parsed.public_output);
    eprintln!("max_proofs_verified: {}", parsed.max_proofs_verified);
    eprintln!("proof deserialized successfully");

    // Decode VK
    let vk_wire =
        MinaBaseVerificationKeyWireStableV1::from_base64(vk_b64).expect("decode vk base64");
    let verification_key: VerificationKey = (&vk_wire).try_into().expect("vk wire -> runtime vk");

    eprintln!("verification_key hash: {:?}", verification_key.hash());

    // Build verifier index + VK wrapper
    let verifier_index = make_zkapp_verifier_index(&verification_key);
    let vk = VK {
        commitments: *verification_key.wrap_index.clone(),
        index: &verifier_index,
        data: (),
    };

    let proof = &parsed.proof;

    // Compute deferred values and run checks
    let deferred_values = compute_deferred_values(proof).expect("compute deferred values");
    let checks_ok = run_checks(proof, vk.index);
    eprintln!("run_checks: {checks_ok}");

    let prover_proof = make_padded_proof_from_p2p(proof).expect("make_padded_proof");
    eprintln!("proof padded successfully");

    let mut public_inputs = vec![Fq::zero(); 40];

    let result = verify_with(&verifier_index, &prover_proof, &public_inputs);

    assert!(result.is_ok(), "invalid proof: {:?}", result.err());
}
