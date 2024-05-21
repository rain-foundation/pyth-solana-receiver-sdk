#[cfg(feature = "quickcheck")]
use quickcheck::Arbitrary;
use {
    crate::{check, error::GetPriceError},
    anchor_lang::prelude::{borsh::BorshSchema, *},
    borsh::{BorshDeserialize, BorshSerialize},
    serde::{Deserialize, Serialize},
    solana_program::pubkey::Pubkey,
};

/// Pyth price updates are bridged to all blockchains via Wormhole.
/// Using the price updates on another chain requires verifying the signatures of the Wormhole guardians.
/// The usual process is to check the signatures for two thirds of the total number of guardians, but this can be cumbersome on Solana because of the transaction size limits,
/// so we also allow for partial verification.
///
/// This enum represents how much a price update has been verified:
/// - If `Full`, we have verified the signatures for two thirds of the current guardians.
/// - If `Partial`, only `num_signatures` guardian signatures have been checked.
///
/// # Warning
/// Using partially verified price updates is dangerous, as it lowers the threshold of guardians that need to collude to produce a malicious price update.
#[derive(AnchorSerialize, AnchorDeserialize, Copy, Clone, PartialEq, BorshSchema, Debug)]
pub enum VerificationLevel {
    Partial { num_signatures: u8 },
    Full,
}

impl VerificationLevel {
    /// Compare two `VerificationLevel`.
    /// `Full` is always greater than `Partial`, and `Partial` with more signatures is greater than `Partial` with fewer signatures.
    pub fn gte(&self, other: VerificationLevel) -> bool {
        match self {
            VerificationLevel::Full => true,
            VerificationLevel::Partial { num_signatures } => match other {
                VerificationLevel::Full => false,
                VerificationLevel::Partial {
                    num_signatures: other_num_signatures,
                } => *num_signatures >= other_num_signatures,
            },
        }
    }
}

/// A price update account. This account is used by the Pyth Receiver program to store a verified price update from a Pyth price feed.
/// It contains:
/// - `write_authority`: The write authority for this account. This authority can close this account to reclaim rent or update the account to contain a different price update.
/// - `verification_level`: The [`VerificationLevel`] of this price update. This represents how many Wormhole guardian signatures have been verified for this price update.
/// - `price_message`: The actual price update.
/// - `posted_slot`: The slot at which this price update was posted.
#[account]
pub struct PriceUpdateV2 {
    pub write_authority: Pubkey,
    pub verification_level: VerificationLevel,
    pub price_message: PriceFeedMessage,
    pub posted_slot: u64,
}

impl PriceUpdateV2 {
    pub const LEN: usize = 8 + 32 + 2 + 32 + 8 + 8 + 4 + 8 + 8 + 8 + 8 + 8;
}

/// A Pyth price.
/// The actual price is `(price ± conf)* 10^exponent`. `publish_time` may be used to check the recency of the price.
#[derive(PartialEq, Debug, Clone, Copy)]
pub struct Price {
    pub price: i64,
    pub conf: u64,
    pub exponent: i32,
    pub publish_time: i64,
}

impl PriceUpdateV2 {
    /// Get a `Price` from a `PriceUpdateV2` account for a given `FeedId`.
    ///
    /// # Warning
    /// This function does not check :
    /// - How recent the price is
    /// - Whether the price update has been verified
    ///
    /// It is therefore unsafe to use this function without any extra checks, as it allows for the possibility of using unverified or outdated price updates.
    pub fn get_price_unchecked(
        &self,
        feed_id: &FeedId,
    ) -> std::result::Result<Price, GetPriceError> {
        check!(
            self.price_message.feed_id == *feed_id,
            GetPriceError::MismatchedFeedId
        );
        Ok(Price {
            price: self.price_message.price,
            conf: self.price_message.conf,
            exponent: self.price_message.exponent,
            publish_time: self.price_message.publish_time,
        })
    }

    /// Get a `Price` from a `PriceUpdateV2` account for a given `FeedId` no older than `maximum_age` with customizable verification level.
    ///
    /// # Warning
    /// Lowering the verification level from `Full` to `Partial` increases the risk of using a malicious price update.
    /// Please read the documentation for [`VerificationLevel`] for more information.
    ///
    /// # Example
    /// ```
    /// use pyth_solana_receiver_sdk::price_update::{get_feed_id_from_hex, VerificationLevel, PriceUpdateV2};
    /// use anchor_lang::prelude::*;
    ///
    /// const MAXIMUM_AGE : u64 = 30;
    /// const FEED_ID: &str = "0xef0d8b6fda2ceba41da15d4095d1da392a0d2f8ed0c6c7bc0f4cfac8c280b56d"; // SOL/USD
    ///
    /// #[derive(Accounts)]
    /// #[instruction(amount_in_usd : u64)]
    /// pub struct ReadPriceAccount<'info> {
    ///     pub price_update: Account<'info, PriceUpdateV2>,
    /// }
    ///
    /// pub fn read_price_account(ctx : Context<ReadPriceAccount>) -> Result<()> {
    ///     let price_update = &mut ctx.accounts.price_update;
    ///     let price = price_update.get_price_no_older_than_with_custom_verification_level(&Clock::get()?, MAXIMUM_AGE, &get_feed_id_from_hex(FEED_ID)?, VerificationLevel::Partial{num_signatures: 5})?;
    ///     Ok(())
    /// }
    ///```
    pub fn get_price_no_older_than_with_custom_verification_level(
        &self,
        clock: &Clock,
        maximum_age: u64,
        feed_id: &FeedId,
        verification_level: VerificationLevel,
    ) -> std::result::Result<Price, GetPriceError> {
        check!(
            self.verification_level.gte(verification_level),
            GetPriceError::InsufficientVerificationLevel
        );
        let price = self.get_price_unchecked(feed_id)?;
        check!(
            price
                .publish_time
                .saturating_add(maximum_age.try_into().unwrap())
                >= clock.unix_timestamp,
            GetPriceError::PriceTooOld
        );
        Ok(price)
    }

    /// Get a `Price` from a `PriceUpdateV2` account for a given `FeedId` no older than `maximum_age` with `Full` verification.
    ///
    /// # Example
    /// ```
    /// use pyth_solana_receiver_sdk::price_update::{get_feed_id_from_hex, PriceUpdateV2};
    /// use anchor_lang::prelude::*;
    ///
    /// const MAXIMUM_AGE : u64 = 30;
    /// const FEED_ID: &str = "0xef0d8b6fda2ceba41da15d4095d1da392a0d2f8ed0c6c7bc0f4cfac8c280b56d"; // SOL/USD
    ///
    /// #[derive(Accounts)]
    /// #[instruction(amount_in_usd : u64)]
    /// pub struct ReadPriceAccount<'info> {
    ///     pub price_update: Account<'info, PriceUpdateV2>,
    /// }
    ///
    /// pub fn read_price_account(ctx : Context<ReadPriceAccount>) -> Result<()> {
    ///     let price_update = &mut ctx.accounts.price_update;
    ///     let price = price_update.get_price_no_older_than(&Clock::get()?, MAXIMUM_AGE, &get_feed_id_from_hex(FEED_ID)?)?;
    ///     Ok(())
    /// }
    ///```
    pub fn get_price_no_older_than(
        &self,
        clock: &Clock,
        maximum_age: u64,
        feed_id: &FeedId,
    ) -> std::result::Result<Price, GetPriceError> {
        self.get_price_no_older_than_with_custom_verification_level(
            clock,
            maximum_age,
            feed_id,
            VerificationLevel::Full,
        )
    }
}

/// Get a `FeedId` from a hex string.
///
/// Price feed ids are a 32 byte unique identifier for each price feed in the Pyth network.
/// They are sometimes represented as a 64 character hex string (with or without a 0x prefix).
///
/// # Example
///
/// ```
/// use pyth_solana_receiver_sdk::price_update::get_feed_id_from_hex;
/// let feed_id = get_feed_id_from_hex("0xef0d8b6fda2ceba41da15d4095d1da392a0d2f8ed0c6c7bc0f4cfac8c280b56d").unwrap();
/// ```
pub fn get_feed_id_from_hex(input: &str) -> std::result::Result<FeedId, GetPriceError> {
    let mut feed_id: FeedId = [0; 32];
    match input.len() {
        66 => feed_id.copy_from_slice(
            &hex::decode(&input[2..]).map_err(|_| GetPriceError::FeedIdNonHexCharacter)?,
        ),
        64 => feed_id.copy_from_slice(
            &hex::decode(input).map_err(|_| GetPriceError::FeedIdNonHexCharacter)?,
        ),
        _ => return Err(GetPriceError::FeedIdMustBe32Bytes),
    }
    Ok(feed_id)
}

/// Id of a feed producing the message. One feed produces one or more messages.
pub type FeedId = [u8; 32];

#[repr(C)]
#[derive(
    Debug,
    Copy,
    Clone,
    PartialEq,
    Serialize,
    Deserialize,
    BorshSchema,
    AnchorDeserialize,
    AnchorSerialize,
)]
pub struct PriceFeedMessage {
    pub feed_id: [u8; 32],
    pub price: i64,
    pub conf: u64,
    pub exponent: i32,
    /// The timestamp of this price update in seconds
    pub publish_time: i64,
    /// The timestamp of the previous price update. This field is intended to allow users to
    /// identify the single unique price update for any moment in time:
    /// for any time t, the unique update is the one such that prev_publish_time < t <= publish_time.
    ///
    /// Note that there may not be such an update while we are migrating to the new message-sending logic,
    /// as some price updates on pythnet may not be sent to other chains (because the message-sending
    /// logic may not have triggered). We can solve this problem by making the message-sending mandatory
    /// (which we can do once publishers have migrated over).
    ///
    /// Additionally, this field may be equal to publish_time if the message is sent on a slot where
    /// where the aggregation was unsuccesful. This problem will go away once all publishers have
    /// migrated over to a recent version of pyth-agent.
    pub prev_publish_time: i64,
    pub ema_price: i64,
    pub ema_conf: u64,
}

#[cfg(feature = "quickcheck")]
impl Arbitrary for PriceFeedMessage {
    fn arbitrary(g: &mut quickcheck::Gen) -> Self {
        let mut id = [0u8; 32];
        for item in &mut id {
            *item = u8::arbitrary(g);
        }

        let publish_time = i64::arbitrary(g);

        PriceFeedMessage {
            id,
            price: i64::arbitrary(g),
            conf: u64::arbitrary(g),
            exponent: i32::arbitrary(g),
            publish_time,
            prev_publish_time: publish_time.saturating_sub(i64::arbitrary(g)),
            ema_price: i64::arbitrary(g),
            ema_conf: u64::arbitrary(g),
        }
    }
}
