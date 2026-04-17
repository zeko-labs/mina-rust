// Run this test with:
// cargo test --test test_verification -- --nocapture

use ledger::{
    proofs::{
        prover::make_padded_proof_from_p2p,
        verification::{
            compute_deferred_values, get_message_for_next_step_proof,
            get_message_for_next_wrap_proof, get_prepared_statement, run_checks, verify_with, VK,
        },
        verifiers::make_zkapp_verifier_index,
    },
    scan_state::transaction_logic::{
        verifiable, zkapp_command::ZkAppCommand, TransactionStatus, WithStatus,
    },
    verifier::common::{check, CheckResult},
    VerificationKey, VerificationKeyWire,
};
use mina_p2p_messages::v2::MinaBaseVerificationKeyWireStableV1;

// Import helpers from lib.rs
use ledger::scan_state::transaction_logic::zkapp_command::verifiable::create;
use verification_test::parse_graphql_zkapp_file;

#[test]
fn test_parse_zkapp_command() {
    let parsed = parse_graphql_zkapp_file("tests/graphql.txt")
        .expect("Failed to parse GraphQL zkapp mutation");

    eprintln!(
        "fee_payer: {:?}",
        parsed.zkapp_command.fee_payer.body.public_key
    );
    eprintln!(
        "account_updates count: {}",
        parsed.zkapp_command.account_updates.len()
    );
    eprintln!("proof parsed successfully");
}

#[test]
fn test_verify_with() {
    let vk_b64 = include_str!("vk.txt");

    // Parse the GraphQL mutation -> wire transaction + proof
    let parsed = parse_graphql_zkapp_file("tests/graphql.txt")
        .expect("Failed to parse GraphQL zkapp mutation");

    let proof = &parsed.proof;

    // Decode VK
    let vk_wire =
        MinaBaseVerificationKeyWireStableV1::from_base64(vk_b64).expect("decode vk base64");
    let verification_key: VerificationKey = (&vk_wire).try_into().expect("vk wire -> runtime vk");

    // Build verifier index + VK wrapper
    let verifier_index = make_zkapp_verifier_index(&verification_key);
    let vk = VK {
        commitments: *verification_key.wrap_index.clone(),
        index: &verifier_index,
        data: (),
    };

    let zkapp_runtime: ZkAppCommand = (&parsed.zkapp_command).try_into().expect("wire -> runtime");

    // Build the verifiable command by providing a VK lookup closure
    let zkapp_verifiable = create(
        &zkapp_runtime,
        false, // is_failed = false
        |_expected_vk_hash, _account_id| {
            // Return our VK for any proved account update
            Ok(VerificationKeyWire::new(verification_key.clone()))
        },
    )
    .expect("verifiable::create");

    let cmd = WithStatus {
        data: verifiable::UserCommand::ZkAppCommand(Box::new(zkapp_verifiable)),
        status: TransactionStatus::Applied,
    };

    let (_vk_from_tx, zkapp_stmt_from_tx, _proof_from_tx) = match check(cmd) {
        CheckResult::ValidAssuming((_valid_cmd, mut xs)) => xs.pop().expect("no vk/stmt/proof"),
        other => panic!("expected ValidAssuming(..), got: {other:?}"),
    };

    // Compute deferred values and run checks
    let deferred_values = compute_deferred_values(proof).expect("compute deferred values");
    let checks_ok = run_checks(proof, vk.index);

    let msg_next_step = get_message_for_next_step_proof(
        &proof.statement.messages_for_next_step_proof,
        &vk.commitments,
        &zkapp_stmt_from_tx,
    )
    .expect("get_message_for_next_step_proof");

    let msg_next_wrap =
        get_message_for_next_wrap_proof(&proof.statement.proof_state.messages_for_next_wrap_proof)
            .expect("get_message_for_next_wrap_proof");

    let prepared_statement = get_prepared_statement(
        &msg_next_step,
        &msg_next_wrap,
        deferred_values,
        &proof.statement.proof_state.sponge_digest_before_evaluations,
    );

    let public_inputs = prepared_statement
        .to_public_input(vk.index.public)
        .expect("prepared_statement -> public inputs");

    let prover_proof = make_padded_proof_from_p2p(proof).expect("make_padded_proof");

    match verify_with(vk.index, &prover_proof, &public_inputs) {
        Ok(()) => assert!(checks_ok, "verify_with OK but run_checks failed"),
        Err(e) => panic!("invalid proof: {e:?}"),
    }
}
