//! Configuration modules for the Monero Marketplace server

pub mod fee;
pub mod platform_wallet;
pub mod price;
pub mod timeout;
pub mod wallet_encryption;

pub use fee::{get_fee_reserve, get_tx_fee, DEFAULT_FEE_RESERVE_ATOMIC, DEFAULT_TX_FEE_ATOMIC};
pub use platform_wallet::{
    get_configured_network, get_platform_wallet_address, get_platform_wallet_config,
    get_refund_fee_bps, get_release_fee_bps, is_mainnet, load_platform_wallet,
    validate_platform_wallet_on_startup, PlatformWalletConfig, PlatformWalletError,
};
pub use price::XmrUsdRate;
pub use timeout::TimeoutConfig;
pub use wallet_encryption::{
    get_wallet_password, is_wallet_encryption_enabled, load_wallet_encryption_config,
    validate_wallet_encryption_on_startup,
};
