use ephemeral_vrf_api::prelude::*;
use ephemeral_vrf_api::verify::verify_dleq;
use solana_curve25519::ristretto::PodRistrettoPoint;
use solana_program::instruction::Instruction;
use steel::*;

/// Process a ProvideObliviousRandomness instruction.
///
/// Verifies the DLEQ proof that `output = sk·T` where T is the client's blinded point
/// and sk is the oracle's registered key. Invokes the callback with the raw OPRF output Z.
/// The client must unblind Z and hash the result to obtain the final randomness.
///
/// Accounts (same layout as ProvideRandomness):
/// 0. [signer]    oracle_info
/// 1. []          program_identity_info
/// 2. []          oracle_data_info
/// 3. [writable]  oracle_queue_info
/// 4. []          callback_program_info
/// 5..            remaining callback accounts
pub fn process_provide_oblivious_randomness(
    accounts: &[AccountInfo<'_>],
    data: &[u8],
) -> ProgramResult {
    let args = ProvideObliviousRandomness::try_from_bytes(data)?;

    let (
        [oracle_info, program_identity_info, oracle_data_info, oracle_queue_info, callback_program_info],
        remaining_accounts,
    ) = accounts.split_at(5)
    else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    oracle_info.is_signer()?;

    oracle_data_info.has_seeds(
        &[ORACLE_DATA, oracle_info.key.to_bytes().as_ref()],
        &ephemeral_vrf_api::ID,
    )?;

    let oracle_data = oracle_data_info.as_account::<Oracle>(&ephemeral_vrf_api::ID)?;

    let queue_index = {
        let data_ref = oracle_queue_info.try_borrow_data()?;
        let header = Queue::try_from_bytes(&data_ref)?;
        header.index
    };
    oracle_queue_info
        .is_writable()?
        .has_owner(&ephemeral_vrf_api::ID)?
        .has_seeds(
            &[QUEUE, oracle_info.key.to_bytes().as_ref(), &[queue_index]],
            &ephemeral_vrf_api::ID,
        )?;

    let removed_item_and_buf = {
        let mut data = oracle_queue_info.try_borrow_mut_data()?;
        if data.len() < 8 {
            return Err(ProgramError::InvalidAccountData);
        }
        let queue_data = &mut data[8..];
        let mut queue_acc = QueueAccount::load(queue_data)?;

        let (index, _item) = {
            let (index, item) = queue_acc
                .find_item_by_id(&args.input)
                .ok_or::<ProgramError>(EphemeralVrfError::RandomnessRequestNotFound.into())?;

            // Reject unknown request types.
            if item.request_type != 1 {
                return Err(ProgramError::InvalidArgument);
            }

            let oracle_in_accounts = {
                let metas = item.account_metas(queue_acc.acc);
                metas
                    .iter()
                    .any(|acc| Pubkey::new_from_array(acc.pubkey).eq(oracle_info.key))
            };
            if oracle_in_accounts {
                return Err(EphemeralVrfError::InvalidCallbackAccounts.into());
            }

            if Clock::get()?.slot <= item.slot {
                return Err(ProgramError::from(
                    EphemeralVrfError::OracleMustProvideInDifferentSlot,
                ));
            }

            (index, item)
        };

        // Extract blinded_point from first 32 bytes of callback_args (before removing item).
        let blinded_point: [u8; 32] = {
            let item_copy = queue_acc.get_item_by_index(index)
                .ok_or(ProgramError::InvalidAccountData)?;
            let args_bytes = item_copy.callback_args(queue_acc.acc);
            if args_bytes.len() < 32 {
                return Err(ProgramError::InvalidAccountData);
            }
            args_bytes[0..32].try_into().map_err(|_| ProgramError::InvalidAccountData)?
        };

        // Verify DLEQ proof: output = sk·T where T = blinded_point, K = oracle public key.
        let verified = verify_dleq(
            &oracle_data.vrf_pubkey,
            &PodRistrettoPoint(blinded_point),
            &args.output,
            &args.r1,
            &args.r2,
            &args.scalar,
        );
        if !verified {
            return Err(EphemeralVrfError::InvalidProof.into());
        }

        let removed_item = queue_acc.remove_item(index)?;
        let metas = removed_item.account_metas(queue_acc.acc).to_vec();
        let disc = removed_item.callback_discriminator(queue_acc.acc).to_vec();
        // Strip the 32-byte blinded_point prefix before forwarding to callback.
        let full_args = removed_item.callback_args(queue_acc.acc);
        let user_args = if full_args.len() >= 32 { full_args[32..].to_vec() } else { vec![] };
        (removed_item, metas, disc, user_args, blinded_point)
    };

    let (removed_item, metas_vec, disc_vec, user_args_vec, _blinded_point) = removed_item_and_buf;

    callback_program_info.has_address(&Pubkey::new_from_array(removed_item.callback_program_id))?;
    let mut accounts_metas = vec![AccountMeta {
        pubkey: *program_identity_info.key,
        is_signer: true,
        is_writable: false,
    }];
    accounts_metas.extend(metas_vec.iter().map(|acc| acc.to_account_meta()));

    // Callback data: discriminator || Z (raw 32-byte OPRF output) || user_args.
    // Client is responsible for: unblind(Z) then hash(unblinded.compress()) = final_seed.
    let mut callback_data = Vec::with_capacity(disc_vec.len() + 32 + user_args_vec.len());
    callback_data.extend_from_slice(&disc_vec);
    callback_data.extend_from_slice(&args.output.0);
    callback_data.extend_from_slice(&user_args_vec);

    let ix = Instruction {
        program_id: Pubkey::new_from_array(removed_item.callback_program_id),
        accounts: accounts_metas,
        data: callback_data,
    };
    let mut all_accounts = vec![callback_program_info.clone()];
    all_accounts.push(program_identity_info.clone());
    all_accounts.extend_from_slice(remaining_accounts);

    let id = program_identity_pda();
    program_identity_info.has_address(&id.0)?;
    let pda_signer_seeds: &[&[&[u8]]] = &[&[IDENTITY, &[id.1]]];
    solana_program::program::invoke_signed(&ix, &all_accounts, pda_signer_seeds)?;

    if oracle_queue_info.key.ne(&DEFAULT_EPHEMERAL_QUEUE) {
        let cost = if removed_item.priority_request == 1 {
            VRF_HIGH_PRIORITY_LAMPORTS_COST
        } else {
            VRF_LAMPORTS_COST
        };
        crate::fees::transfer_fee(oracle_queue_info, oracle_info, cost)?;
    }

    Ok(())
}
