// Run with:
// cargo test --test test_apply -- --nocapture

use mina_core::constants::constraint_constants;

use ledger::{
    proofs::verification::{
        compute_deferred_values, get_message_for_next_step_proof,
        get_message_for_next_wrap_proof, get_prepared_statement, run_checks, verify_with, VK,
    },
    proofs::{prover::make_padded_proof_from_p2p, verifiers::make_zkapp_verifier_index},
    scan_state::{
        currency::{Amount, Balance, Length, Magnitude, Slot},
        transaction_logic::{
            local_state::{apply_zkapp_command_first_pass, apply_zkapp_command_second_pass},
            protocol_state::{EpochData, EpochLedger, ProtocolStateView},
            zkapp_command::{verifiable::create, ZkAppCommand},
            TransactionStatus, WithStatus,
        },
    },
    verifier::common::{check, CheckResult},
    Account, AccountId, AuthRequired, BaseLedger, Mask, TokenId,
    VerificationKey, VerificationKeyWire, ZkAppAccount,
};
use ark_ff::Zero;
use mina_curves::pasta::Fp;
use mina_p2p_messages::v2::MinaBaseVerificationKeyWireStableV1;

use verification_test::parse_graphql_zkapp_file;

// ---------------------------------------------------------------------------
// Minimal L2 state
// ---------------------------------------------------------------------------

struct L2State {
    balance:    u64, // nanomina, used to seed all accounts
    block_slot: u32,
}

// ---------------------------------------------------------------------------
// ProtocolStateView — all fields zeroed, only global_slot matters here
// ---------------------------------------------------------------------------

fn minimal_state_view(block_slot: u32) -> ProtocolStateView {
    let zero_epoch = EpochData {
        ledger: EpochLedger {
            hash:           Fp::zero(),
            total_currency: Amount::zero(),
        },
        seed:             Fp::zero(),
        start_checkpoint: Fp::zero(),
        lock_checkpoint:  Fp::zero(),
        epoch_length:     Length::from_u32(0),
    };

    ProtocolStateView {
        snarked_ledger_hash:       Fp::zero(),
        blockchain_length:         Length::from_u32(0),
        min_window_density:        Length::from_u32(0),
        total_currency:            Amount::zero(),
        global_slot_since_genesis: Slot::from_u32(block_slot),
        staking_epoch_data:        zero_epoch.clone(),
        next_epoch_data:           zero_epoch,
    }
}

// ---------------------------------------------------------------------------
// Test
// ---------------------------------------------------------------------------

#[test]
fn test_apply_zkapp_command() {
    // ------------------------------------------------------------------
    // 1. Parse — same files as test_verify_with
    // ------------------------------------------------------------------
    let vk_b64 = include_str!("vk.txt");
    let parsed = parse_graphql_zkapp_file("tests/graphql.txt")
        .expect("failed to parse GraphQL mutation");

    let proof = &parsed.proof;

    let vk_wire = MinaBaseVerificationKeyWireStableV1::from_base64(vk_b64)
        .expect("decode vk base64");
    let verification_key: VerificationKey = (&vk_wire)
        .try_into()
        .expect("vk wire -> runtime");

    let cmd: ZkAppCommand = (&parsed.zkapp_command)
        .try_into()
        .expect("wire -> runtime ZkAppCommand");

    eprintln!("fee_payer : {:?}", cmd.fee_payer.body.public_key);
    eprintln!("fee       : {:?}", cmd.fee_payer.body.fee);
    eprintln!("nonce     : {:?}", cmd.fee_payer.body.nonce);
    eprintln!("updates   : {}", cmd.account_updates.0.len());

    // ------------------------------------------------------------------
    // 2. L2 state
    // ------------------------------------------------------------------
    let l2 = L2State {
        balance:    10_000_000_000, // 10 MINA in nanomina
        block_slot: 100,
    };

    // ------------------------------------------------------------------
    // 3. Build in-memory ledger
    //
    // The transaction (from the GraphQL mutation) has:
    //   - feePayer:       B62qk6bjA5... (MINA token, nonce 0)
    //   - accountUpdate:  B62qkqy6Uj... (custom token wSHV2S4q..., proved auth)
    //     · precondition: state[0] == Fp(0)
    //     · update:       state[0] = Fp(1)
    //     · authKind:     isProved=true, vkHash=6975621654...
    //
    // For apply() to succeed we must pre-populate the zkapp account with:
    //   1. permissions.edit_state = AuthRequired::Proof
    //   2. zkapp.verification_key = Some(our VK)   — hash must equal 6975621654...
    //   3. zkapp.app_state[0]     = Fp::zero()     — satisfies the precondition
    // ------------------------------------------------------------------
    let mut ledger = Mask::create(35);

    // --- Fee payer (B62qk6bjA5...) ---
    let fee_payer_id = AccountId::new(
        cmd.fee_payer.body.public_key.clone(),
        TokenId::default(),
    );
    let mut fee_payer_acct = Account::initialize(&fee_payer_id);
    fee_payer_acct.balance = Balance::from_u64(l2.balance);
    fee_payer_acct.nonce   = cmd.fee_payer.body.nonce;
    ledger
        .get_or_create_account(fee_payer_id, fee_payer_acct)
        .expect("insert fee payer");

    // --- zkApp account (B62qkqy6Uj...) — inserted before the generic loop ---
    //
    // Pull public_key and token_id from the parsed command so that the
    // AccountId matches exactly what apply() will look up in the ledger.
    let zkapp_update = &cmd.account_updates.0[0];
    let zkapp_id = AccountId::new(
        zkapp_update.elt.account_update.body.public_key.clone(),
        zkapp_update.elt.account_update.body.token_id.clone(),
    );

    let mut zkapp_acct = Account::initialize(&zkapp_id);
    zkapp_acct.balance = Balance::from_u64(l2.balance);

    // Default permissions have edit_state = Signature, which causes
    // UpdateNotPermittedAppState. Override to Proof.
    zkapp_acct.permissions.edit_state = AuthRequired::Proof;

    // Attach the VK so the hash check passes (fixes UnexpectedVerificationKeyHash).
    // Seed app_state[0] = 0 to satisfy the account precondition state[0] == "0".
    let mut zk = ZkAppAccount::default();
    zk.verification_key = Some(VerificationKeyWire::new(verification_key.clone()));
    zk.app_state[0]     = Fp::zero();
    zkapp_acct.zkapp = Some(Box::new(zk));

    ledger
        .get_or_create_account(zkapp_id, zkapp_acct)
        .expect("insert zkapp account");

    // --- All remaining referenced accounts (skip already-inserted ones) ---
    for account_id in cmd.accounts_referenced() {
        if ledger.location_of_account(&account_id).is_some() {
            continue;
        }
        let mut acct = Account::initialize(&account_id);
        acct.balance = Balance::from_u64(l2.balance);
        ledger
            .get_or_create_account(account_id, acct)
            .expect("insert account");
    }

    let root_before = ledger.merkle_root();
    eprintln!("root before : {:?}", root_before);

    // ------------------------------------------------------------------
    // 4. Apply: first pass (fee payer) then second pass (all updates)
    // ------------------------------------------------------------------
    let state_view  = minimal_state_view(l2.block_slot);
    let global_slot = Slot::from_u32(l2.block_slot);

    let partially_applied = apply_zkapp_command_first_pass(
        constraint_constants(),
        global_slot,
        &state_view,
        None, // fee_excess      → defaults to Signed::zero()
        None, // supply_increase → defaults to Signed::zero()
        &mut ledger,
        &cmd,
    )
    .expect("first pass failed");

    eprintln!("✓ first pass OK");

    let applied = apply_zkapp_command_second_pass(
        constraint_constants(),
        &mut ledger,
        partially_applied,
    )
    .expect("second pass failed");

    let root_after = ledger.merkle_root();
    eprintln!("✓ second pass OK");
    eprintln!("root after  : {:?}", root_after);
    eprintln!("status      : {:?}", applied.command.status);

    // Print new app_state[0] to confirm the update was applied
    let zkapp_id2 = AccountId::new(
        zkapp_update.elt.account_update.body.public_key.clone(),
        zkapp_update.elt.account_update.body.token_id.clone(),
    );
    if let Some(loc) = ledger.location_of_account(&zkapp_id2) {
        if let Some(acct) = ledger.get(loc) {
            if let Some(zk) = &acct.zkapp {
                eprintln!("app_state[0] after : {:?}", zk.app_state[0]);
            }
        }
    }

    // ------------------------------------------------------------------
    // 5. Assert the transaction was Applied (not Failed)
    // ------------------------------------------------------------------
    assert_eq!(
        applied.command.status,
        TransactionStatus::Applied,
        "transaction failed: {:?}",
        applied.command.status
    );

    eprintln!("✓ apply assertions passed");

    // ------------------------------------------------------------------
    // 6. Proof verification — same as test_verify_with
    // ------------------------------------------------------------------
    let cmd_verifiable = create(
        &cmd,
        false,
        |_hash, _id| Ok(VerificationKeyWire::new(verification_key.clone())),
    )
    .expect("verifiable::create");

    let with_status = WithStatus {
        data:   ledger::scan_state::transaction_logic::verifiable::UserCommand::ZkAppCommand(
                    Box::new(cmd_verifiable),
                ),
        status: TransactionStatus::Applied,
    };

    let (_vk_ret, zkapp_stmt, _proof_ret) = match check(with_status) {
        CheckResult::ValidAssuming((_valid, mut xs)) => xs.pop().expect("empty"),
        other => panic!("expected ValidAssuming, got: {other:?}"),
    };

    let verifier_index = make_zkapp_verifier_index(&verification_key);
    let vk = VK {
        commitments: *verification_key.wrap_index.clone(),
        index:       &verifier_index,
        data:        (),
    };

    let deferred_values = compute_deferred_values(proof)
        .expect("compute_deferred_values");
    let checks_ok = run_checks(proof, vk.index);

    let msg_next_step = get_message_for_next_step_proof(
        &proof.statement.messages_for_next_step_proof,
        &vk.commitments,
        &zkapp_stmt,
    )
    .expect("get_message_for_next_step_proof");

    let msg_next_wrap = get_message_for_next_wrap_proof(
        &proof.statement.proof_state.messages_for_next_wrap_proof,
    )
    .expect("get_message_for_next_wrap_proof");

    let prepared = get_prepared_statement(
        &msg_next_step,
        &msg_next_wrap,
        deferred_values,
        &proof.statement.proof_state.sponge_digest_before_evaluations,
    );

    let public_inputs = prepared
        .to_public_input(vk.index.public)
        .expect("prepared -> public inputs");

    let prover_proof = make_padded_proof_from_p2p(proof)
        .expect("make_padded_proof");

    match verify_with(vk.index, &prover_proof, &public_inputs) {
        Ok(()) => {
            assert!(checks_ok, "verify_with OK but run_checks failed");
            eprintln!("✓ Pickles proof valid");
        }
        Err(e) => panic!("invalid proof: {e:?}"),
    }

    eprintln!("✓ transaction valid for this L2 state");
}