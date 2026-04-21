// Run with:
// cargo test --test test_zkapp -- --nocapture

use mina_core::constants::constraint_constants;

use ark_ff::Zero;
use ledger::{
    proofs::verification::verify_zkapp,
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
    verifier::get_srs,
    Account, AccountId, AuthRequired, BaseLedger, Mask, TokenId, VerificationKey,
    VerificationKeyWire, ZkAppAccount,
};
use mina_curves::pasta::Fp;
use mina_p2p_messages::v2::MinaBaseVerificationKeyWireStableV1;

use verification_test::parse_graphql_zkapp_file;

// ---------------------------------------------------------------------------
// Minimal L2 state
// ---------------------------------------------------------------------------

struct L2State {
    balance: u64,
    block_slot: u32,
}

// ---------------------------------------------------------------------------
// ProtocolStateView — all fields zeroed, only global_slot matters here
// ---------------------------------------------------------------------------

fn minimal_state_view(block_slot: u32) -> ProtocolStateView {
    let zero_epoch = EpochData {
        ledger: EpochLedger {
            hash: Fp::zero(),
            total_currency: Amount::zero(),
        },
        seed: Fp::zero(),
        start_checkpoint: Fp::zero(),
        lock_checkpoint: Fp::zero(),
        epoch_length: Length::from_u32(0),
    };

    ProtocolStateView {
        snarked_ledger_hash: Fp::zero(),
        blockchain_length: Length::from_u32(0),
        min_window_density: Length::from_u32(0),
        total_currency: Amount::zero(),
        global_slot_since_genesis: Slot::from_u32(block_slot),
        staking_epoch_data: zero_epoch.clone(),
        next_epoch_data: zero_epoch,
    }
}

// ---------------------------------------------------------------------------
// Test
// ---------------------------------------------------------------------------

#[test]
fn test_apply_zkapp_command() {
    // ------------------------------------------------------------------
    // 1. Parse
    // ------------------------------------------------------------------
    let vk_b64 = include_str!("vk.txt");
    let parsed =
        parse_graphql_zkapp_file("tests/graphql.txt").expect("failed to parse GraphQL mutation");

    let vk_wire =
        MinaBaseVerificationKeyWireStableV1::from_base64(vk_b64).expect("decode vk base64");
    let verification_key: VerificationKey = (&vk_wire).try_into().expect("vk wire -> runtime");

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
        balance: 10_000_000_000,
        block_slot: 100,
    };

    // ------------------------------------------------------------------
    // 3. Build in-memory ledger
    // ------------------------------------------------------------------
    let mut ledger = Mask::create(35);

    let fee_payer_id = AccountId::new(cmd.fee_payer.body.public_key.clone(), TokenId::default());
    let mut fee_payer_acct = Account::initialize(&fee_payer_id);
    fee_payer_acct.balance = Balance::from_u64(l2.balance);
    fee_payer_acct.nonce = cmd.fee_payer.body.nonce;
    ledger
        .get_or_create_account(fee_payer_id, fee_payer_acct)
        .expect("insert fee payer");

    let zkapp_update = &cmd.account_updates.0[0];
    let zkapp_id = AccountId::new(
        zkapp_update.elt.account_update.body.public_key.clone(),
        zkapp_update.elt.account_update.body.token_id.clone(),
    );

    let mut zkapp_acct = Account::initialize(&zkapp_id);
    zkapp_acct.balance = Balance::from_u64(l2.balance);
    zkapp_acct.permissions.edit_state = AuthRequired::Proof;

    let mut zk = ZkAppAccount::default();
    zk.verification_key = Some(VerificationKeyWire::new(verification_key.clone()));
    zk.app_state[0] = Fp::zero();
    zkapp_acct.zkapp = Some(Box::new(zk));

    ledger
        .get_or_create_account(zkapp_id, zkapp_acct)
        .expect("insert zkapp account");

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

    eprintln!("root before : {:?}", ledger.merkle_root());

    // ------------------------------------------------------------------
    // 4. Apply: first pass then second pass
    // ------------------------------------------------------------------
    let state_view = minimal_state_view(l2.block_slot);
    let global_slot = Slot::from_u32(l2.block_slot);

    let partially_applied = apply_zkapp_command_first_pass(
        constraint_constants(),
        global_slot,
        &state_view,
        None,
        None,
        &mut ledger,
        &cmd,
    )
    .expect("first pass failed");

    eprintln!("✓ first pass OK");

    let applied =
        apply_zkapp_command_second_pass(constraint_constants(), &mut ledger, partially_applied)
            .expect("second pass failed");

    eprintln!("✓ second pass OK");
    eprintln!("root after  : {:?}", ledger.merkle_root());
    eprintln!("status      : {:?}", applied.command.status);

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
    // 6. Proof verification via verify_zkapp
    // ------------------------------------------------------------------
    let cmd_verifiable = create(&cmd, false, |_hash, _id| {
        Ok(VerificationKeyWire::new(verification_key.clone()))
    })
    .expect("verifiable::create");

    let with_status = WithStatus {
        data: ledger::scan_state::transaction_logic::verifiable::UserCommand::ZkAppCommand(
            Box::new(cmd_verifiable),
        ),
        status: TransactionStatus::Applied,
    };

    let (_, zkapp_stmt, _) = match check(with_status) {
        CheckResult::ValidAssuming((_valid, mut xs)) => xs.pop().expect("empty"),
        other => panic!("expected ValidAssuming, got: {other:?}"),
    };

    let srs = get_srs::<Fp>();
    assert!(
        verify_zkapp(&verification_key, &zkapp_stmt, &parsed.proof, &srs),
        "Pickles proof invalid"
    );

    eprintln!("✓ Pickles proof valid");
    eprintln!("✓ transaction valid for this L2 state");
}
