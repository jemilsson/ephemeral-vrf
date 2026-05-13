use ephemeral_vrf_api::prelude::*;
use solana_curve25519::ristretto::{multiply_ristretto, PodRistrettoPoint};
use solana_curve25519::scalar::PodScalar;
use solana_program::hash::hashv;
use solana_program::msg;
use solana_program::program::invoke;
use solana_program::system_instruction;
use solana_program::sysvar::slot_hashes;
use steel::*;

/// Process a RequestObliviousRandomness instruction.
///
/// Accounts (same layout as RequestRandomness):
/// 0. [signer]  signer
/// 1. [signer]  program_identity_info
/// 2. []        oracle_queue_info
/// 3. []        system_program_info
/// 4. []        slothashes_account_info
pub fn process_request_oblivious_randomness(
    accounts: &[AccountInfo<'_>],
    data: &[u8],
) -> ProgramResult {
    let args = RequestObliviousRandomness::try_from_bytes(data)
        .map_err(|_| ProgramError::InvalidInstructionData)?;

    let [signer_info, program_identity_info, oracle_queue_info, system_program_info, slothashes_account_info] =
        accounts
    else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    signer_info.is_signer()?;
    program_identity_info
        .has_seeds(&[IDENTITY], &args.callback_program_id)?
        .is_signer()?;

    // Reject identity point (all-zeros encoding).
    if args.blinded_point == [0u8; 32] {
        return Err(ProgramError::InvalidArgument);
    }
    // Validate it decompresses as a valid Ristretto point by attempting a multiply.
    // scalar::ONE = 1, so 1*T == T iff T is a valid point.
    let one_scalar = PodScalar([
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ]);
    multiply_ristretto(&one_scalar, &PodRistrettoPoint(args.blinded_point))
        .ok_or(ProgramError::InvalidArgument)?;

    // Ensure callback_args includes the 32-byte blinded_point prefix.
    if args.callback_args.len() < 32 {
        return Err(ProgramError::InvalidInstructionData);
    }

    slothashes_account_info.is_sysvar(&slot_hashes::id())?;
    let slothash: [u8; 32] = slothashes_account_info.try_borrow_data()?[16..48]
        .try_into()
        .map_err(|_| ProgramError::UnsupportedSysvar)?;
    let slot = Clock::get()?.slot;
    let time = Clock::get()?.unix_timestamp;

    {
        let mut data = oracle_queue_info.try_borrow_mut_data()?;
        if data.len() < 8 {
            return Err(ProgramError::InvalidAccountData);
        }
        let queue_data = &mut data[8..];
        let mut queue_acc = QueueAccount::load(queue_data)?;

        let idx = queue_acc.len() as u32;
        let combined_hash = hashv(&[
            &args.blinded_point,
            &slot.to_le_bytes(),
            &slothash,
            &args.callback_discriminator,
            &args.callback_program_id.to_bytes(),
            &time.to_le_bytes(),
            &idx.to_le_bytes(),
        ]);

        msg!("Idx: {}", idx);

        if args.callback_discriminator.len() > 8 {
            return Err(ProgramError::from(EphemeralVrfError::ArgumentSizeTooLarge));
        }

        let metas = args
            .callback_accounts_metas
            .iter()
            .map(|ca| (*ca).into())
            .collect::<Vec<CompactAccountMeta>>();

        let base_item = QueueItem {
            slot,
            id: combined_hash.to_bytes(),
            callback_program_id: args.callback_program_id.to_bytes(),
            callback_discriminator_offset: 0,
            metas_offset: 0,
            args_offset: 0,
            callback_discriminator_len: 0,
            metas_len: 0,
            args_len: 0,
            priority_request: 0,
            used: 0,
            request_type: 1, // OPRF request
            _padding: [0u8; 3],
        };
        // blinded_point is already prepended to callback_args in the SDK helper.
        queue_acc.add_item(
            &base_item,
            &args.callback_discriminator,
            &metas,
            &args.callback_args,
        )?;
    }

    if oracle_queue_info.key.ne(&DEFAULT_EPHEMERAL_QUEUE) {
        invoke(
            &system_instruction::transfer(signer_info.key, oracle_queue_info.key, VRF_LAMPORTS_COST),
            &[
                signer_info.clone(),
                oracle_queue_info.clone(),
                system_program_info.clone(),
            ],
        )?;
    }

    Ok(())
}
