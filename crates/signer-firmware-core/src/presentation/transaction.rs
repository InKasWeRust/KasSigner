//! Pure transaction-screen touch reducer.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionScreen {
    Guide { seed_loaded: bool },
    ScanQr { return_target: ScanReturn },
    Review,
    Confirm,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanReturn {
    MultisigAddKey(u8),
    MainMenu,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionEffect {
    None,
    GuideBack,
    DeriveAccount,
    BeginScan,
    ScanBack(ScanReturn),
    ReviewBack,
    ReviewAdvance,
    ConfirmBack,
    ConfirmChoice(u8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransactionDecision {
    pub effect: TransactionEffect,
    pub redraw: bool,
}

pub fn reduce_touch(
    screen: TransactionScreen,
    x: u16,
    y: u16,
    is_back: bool,
) -> TransactionDecision {
    match screen {
        TransactionScreen::Guide { seed_loaded } => reduce_guide(seed_loaded, x, y, is_back),
        TransactionScreen::ScanQr { return_target } => reduce_scan(return_target, x, y),
        TransactionScreen::Review => reduce_review(x, y, is_back),
        TransactionScreen::Confirm => reduce_confirm(x, y, is_back),
    }
}

fn reduce_guide(seed_loaded: bool, x: u16, y: u16, is_back: bool) -> TransactionDecision {
    if is_back {
        return TransactionDecision {
            effect: TransactionEffect::GuideBack,
            redraw: true,
        };
    }
    if !seed_loaded || !(190..=234).contains(&y) {
        return TransactionDecision {
            effect: TransactionEffect::None,
            redraw: false,
        };
    }
    let effect = if (25..=159).contains(&x) {
        TransactionEffect::DeriveAccount
    } else if (161..=295).contains(&x) {
        TransactionEffect::BeginScan
    } else {
        TransactionEffect::None
    };
    TransactionDecision {
        redraw: effect != TransactionEffect::None,
        effect,
    }
}

fn reduce_scan(return_target: ScanReturn, x: u16, y: u16) -> TransactionDecision {
    let effect = if x <= 48 && y <= 48 {
        TransactionEffect::ScanBack(return_target)
    } else {
        TransactionEffect::None
    };
    TransactionDecision {
        effect,
        redraw: false,
    }
}

fn reduce_review(x: u16, y: u16, is_back: bool) -> TransactionDecision {
    let effect = if is_back {
        TransactionEffect::ReviewBack
    } else if (205..=305).contains(&x) && (194..=232).contains(&y) {
        TransactionEffect::ReviewAdvance
    } else {
        TransactionEffect::None
    };
    TransactionDecision {
        effect,
        redraw: effect != TransactionEffect::None,
    }
}

fn reduce_confirm(x: u16, y: u16, is_back: bool) -> TransactionDecision {
    let effect = if is_back {
        TransactionEffect::ConfirmBack
    } else if (15..=105).contains(&x) && (188..=228).contains(&y) {
        TransactionEffect::ConfirmChoice(0)
    } else if (215..=305).contains(&x) && (188..=228).contains(&y) {
        TransactionEffect::ConfirmChoice(1)
    } else if (115..=205).contains(&x) && (188..=228).contains(&y) {
        TransactionEffect::ConfirmChoice(2)
    } else {
        TransactionEffect::None
    };
    TransactionDecision {
        effect,
        redraw: effect != TransactionEffect::None,
    }
}
