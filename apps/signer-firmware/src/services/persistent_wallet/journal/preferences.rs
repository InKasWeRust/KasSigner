//! Versioned device-persistent display/audio preferences stored in the config journal.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::services::persistent_wallet) struct DevicePreferences {
    pub(super) flags: u8,
    pub(super) dim_timeout_code: u8,
}

impl Default for DevicePreferences {
    fn default() -> Self {
        Self { flags: Self::STARTUP_SOUND, dim_timeout_code: 0 }
    }
}

impl DevicePreferences {
    const STARTUP_SOUND: u8 = 1 << 0;
    const REQUIRE_PIN_AFTER_DIM: u8 = 1 << 1;
    const NETWORK_SHIFT: u8 = 2;
    const NETWORK_MASK: u8 = 0b11 << Self::NETWORK_SHIFT;
    pub(super) const KNOWN_MASK: u8 =
        Self::STARTUP_SOUND | Self::REQUIRE_PIN_AFTER_DIM | Self::NETWORK_MASK;

    #[cfg(feature = "m5stack")]
    pub const fn startup_sound_enabled(self) -> bool {
        self.flags & Self::STARTUP_SOUND != 0
    }

    pub const fn require_pin_after_dim(self) -> bool {
        self.flags & Self::REQUIRE_PIN_AFTER_DIM != 0
    }

    pub const fn dim_timeout_code(self) -> u8 { self.dim_timeout_code }

    pub const fn wallet_network(self) -> crate::wallet::seed_manager::WalletNetwork {
        match crate::wallet::seed_manager::WalletNetwork::from_preference_code(
            (self.flags & Self::NETWORK_MASK) >> Self::NETWORK_SHIFT,
        ) {
            Some(network) => network,
            None => crate::wallet::seed_manager::WalletNetwork::Mainnet,
        }
    }

    pub const fn wallet_network_code_valid(self) -> bool {
        crate::wallet::seed_manager::WalletNetwork::from_preference_code(
            (self.flags & Self::NETWORK_MASK) >> Self::NETWORK_SHIFT,
        ).is_some()
    }

    #[cfg(feature = "m5stack")]
    pub fn with_startup_sound(mut self, enabled: bool) -> Self {
        super::set_flag(&mut self.flags, Self::STARTUP_SOUND, enabled);
        self
    }

    pub fn with_require_pin_after_dim(mut self, enabled: bool) -> Self {
        super::set_flag(&mut self.flags, Self::REQUIRE_PIN_AFTER_DIM, enabled);
        self
    }

    pub fn with_dim_timeout_code(mut self, code: u8) -> Self {
        self.dim_timeout_code = code.min(4);
        self
    }

    pub fn with_wallet_network(mut self, network: crate::wallet::seed_manager::WalletNetwork) -> Self {
        self.flags &= !Self::NETWORK_MASK;
        self.flags |= network.preference_code() << Self::NETWORK_SHIFT;
        self
    }
}

