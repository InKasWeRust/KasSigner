use crate::{
    hw::display,
    runtime::data::AppData,
    wallet::mnemonic,
};

const DICE_X: [u16; 3] = [10, 110, 210];
const DICE_Y: [u16; 2] = [70, 135];
const DIE_WIDTH: u16 = 100;
const DIE_HEIGHT: u16 = 65;

pub(super) fn handle(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    x: u16,
    y: u16,
    is_back: bool,
) -> bool {
    if is_back {
        ad.wallet.seeds.dice_collector.zeroize();
        let route = if ad.wallet.seeds.pending_seed_entropy_valid {
            crate::runtime::navigation::route!(StorageSeedDiceCountChoice)
        } else {
            crate::runtime::navigation::route!(SeedToolsMenu)
        };
        crate::runtime::effects::route(ad, route);
        return true;
    }

    if let Some(value) = tapped_die(x, y) {
        return add_roll(ad, boot_display, value);
    }

    if (100..=220).contains(&x) && y >= 200 && ad.wallet.seeds.dice_collector.count > 0 {
        ad.wallet.seeds.dice_collector.undo();
        log!(
            "   Dice undo ({}/{})",
            ad.wallet.seeds.dice_collector.count,
            ad.wallet.seeds.dice_collector.target
        );
        update_progress(ad, boot_display);
    }
    false
}

fn tapped_die(x: u16, y: u16) -> Option<u8> {
    for value in 1u8..=6 {
        let row = ((value - 1) / 3) as usize;
        let column = ((value - 1) % 3) as usize;
        if (DICE_X[column]..DICE_X[column] + DIE_WIDTH).contains(&x)
            && (DICE_Y[row]..DICE_Y[row] + DIE_HEIGHT).contains(&y)
        {
            return Some(value);
        }
    }
    None
}

fn add_roll(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    value: u8,
) -> bool {
    ad.wallet.seeds.dice_collector.add_roll(value);
    log!(
        "   Dice: {} ({}/{})",
        value,
        ad.wallet.seeds.dice_collector.count,
        ad.wallet.seeds.dice_collector.target
    );

    if ad.wallet.seeds.dice_collector.is_complete() {
        generate_seed(ad, boot_display);
        true
    } else {
        update_progress(ad, boot_display);
        false
    }
}

fn generate_seed(ad: &mut AppData, boot_display: &mut display::BootDisplay<'_>) {
    boot_display.draw_saving_screen("Mixing dice entropy...");
    let mut dice = core::mem::replace(
        &mut ad.wallet.seeds.dice_collector,
        mnemonic::DiceCollector::new_12_word(),
    );
    if ad.wallet.seeds.pending_seed_entropy_valid {
        let rolls = dice.count;
        if crate::runtime::interactions::menu::seed_generation::mix_dice_into_staged(ad, &mut dice) {
            log!("   Added {} dice rolls; optional touch choice follows", rolls);
        } else {
            log!("   Additive dice entropy rejected");
            crate::runtime::interactions::persistence::retry_seed_source_choice(ad);
        }
        return;
    }

    let word_count = if dice.target >= 198 { 24 } else { 12 };
    ad.wallet.seeds.mnemonic_indices = mnemonic::generate_from_dice(word_count, &mut dice);
    ad.wallet.seeds.word_count = word_count;
    log!("   Dice seed generated ({} words)", word_count);
    ad.wallet.seeds.pp_input.reset();
    crate::runtime::effects::route(ad, crate::runtime::navigation::route!(PassphraseChoice));
}

fn update_progress(ad: &AppData, boot_display: &mut display::BootDisplay<'_>) {
    boot_display.update_dice_progress(
        ad.wallet.seeds.dice_collector.count,
        ad.wallet.seeds.dice_collector.target,
    );
}
