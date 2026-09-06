use crate::presentation::{
    render::{
        address_render_model, select_public_key, word_count_title, AddressRenderInput,
        CHANGE_CACHE_SIZE, RECEIVE_CACHE_SIZE,
    },
    seed_qr_grid::{reduce_grid, SeedQrGridEffect, SeedQrGridState},
    transaction::{
        reduce_touch, ScanReturn, TransactionDecision, TransactionEffect, TransactionScreen,
    },
};

#[test]
fn seed_qr_grid_moves_clamps_and_exits() {
    let start = SeedQrGridState {
        pan_x: 2,
        pan_y: 3,
        compact: false,
    };
    assert_eq!(
        reduce_grid(start, 29, 10, 60, false),
        SeedQrGridEffect::Move(SeedQrGridState { pan_x: 1, ..start })
    );
    assert_eq!(
        reduce_grid(start, 29, 10, 150, false),
        SeedQrGridEffect::Move(SeedQrGridState { pan_x: 3, ..start })
    );
    assert_eq!(
        reduce_grid(start, 29, 300, 60, false),
        SeedQrGridEffect::Move(SeedQrGridState { pan_y: 2, ..start })
    );
    assert_eq!(
        reduce_grid(start, 29, 300, 150, false),
        SeedQrGridEffect::Move(SeedQrGridState { pan_y: 4, ..start })
    );
    assert_eq!(
        reduce_grid(start, 29, 160, 120, false),
        SeedQrGridEffect::None
    );
    assert_eq!(reduce_grid(start, 29, 0, 0, true), SeedQrGridEffect::Exit);
    let edge = SeedQrGridState {
        pan_x: 14,
        pan_y: 14,
        compact: true,
    };
    assert_eq!(
        reduce_grid(edge, 21, 10, 150, false),
        SeedQrGridEffect::None
    );
}

#[test]
fn transaction_guide_scan_review_and_confirm_are_characterized() {
    assert_eq!(
        reduce_touch(
            TransactionScreen::Guide { seed_loaded: false },
            50,
            200,
            false
        ),
        TransactionDecision {
            effect: TransactionEffect::None,
            redraw: false
        }
    );
    assert_eq!(
        reduce_touch(
            TransactionScreen::Guide { seed_loaded: true },
            50,
            200,
            true
        )
        .effect,
        TransactionEffect::GuideBack
    );
    assert_eq!(
        reduce_touch(
            TransactionScreen::Guide { seed_loaded: true },
            50,
            180,
            false
        ),
        TransactionDecision {
            effect: TransactionEffect::None,
            redraw: false
        }
    );
    assert_eq!(
        reduce_touch(
            TransactionScreen::Guide { seed_loaded: true },
            50,
            200,
            false
        )
        .effect,
        TransactionEffect::DeriveAccount
    );
    assert_eq!(
        reduce_touch(
            TransactionScreen::Guide { seed_loaded: true },
            200,
            200,
            false
        )
        .effect,
        TransactionEffect::BeginScan
    );
    assert_eq!(
        reduce_touch(
            TransactionScreen::Guide { seed_loaded: true },
            160,
            200,
            false
        ),
        TransactionDecision {
            effect: TransactionEffect::None,
            redraw: false
        }
    );
    let scan = TransactionScreen::ScanQr {
        return_target: ScanReturn::MultisigAddKey(2),
    };
    assert_eq!(
        reduce_touch(scan, 48, 48, false).effect,
        TransactionEffect::ScanBack(ScanReturn::MultisigAddKey(2))
    );
    assert_eq!(
        reduce_touch(scan, 49, 48, false).effect,
        TransactionEffect::None
    );
    assert_eq!(
        reduce_touch(scan, 48, 49, false).effect,
        TransactionEffect::None
    );
    let main_scan = TransactionScreen::ScanQr {
        return_target: ScanReturn::MainMenu,
    };
    assert_eq!(
        reduce_touch(main_scan, 1, 1, false).effect,
        TransactionEffect::ScanBack(ScanReturn::MainMenu)
    );
    assert_eq!(
        reduce_touch(TransactionScreen::Review, 0, 0, true).effect,
        TransactionEffect::ReviewBack
    );
    assert_eq!(
        reduce_touch(TransactionScreen::Review, 0, 0, false).effect,
        TransactionEffect::None
    );
    assert_eq!(
        reduce_touch(TransactionScreen::Review, 260, 210, false).effect,
        TransactionEffect::ReviewAdvance
    );
    assert_eq!(
        reduce_touch(TransactionScreen::Confirm, 0, 0, true).effect,
        TransactionEffect::ConfirmBack
    );
    assert_eq!(
        reduce_touch(TransactionScreen::Confirm, 60, 208, false).effect,
        TransactionEffect::ConfirmChoice(0)
    );
    assert_eq!(
        reduce_touch(TransactionScreen::Confirm, 260, 208, false).effect,
        TransactionEffect::ConfirmChoice(1)
    );
    assert_eq!(
        reduce_touch(TransactionScreen::Confirm, 160, 208, false).effect,
        TransactionEffect::ConfirmChoice(2)
    );
    assert_eq!(
        reduce_touch(TransactionScreen::Confirm, 10, 10, false),
        TransactionDecision {
            effect: TransactionEffect::None,
            redraw: false
        }
    );
}

fn caches() -> (
    [[u8; 32]; RECEIVE_CACHE_SIZE],
    [[u8; 32]; CHANGE_CACHE_SIZE],
) {
    let mut receive = [[0; 32]; RECEIVE_CACHE_SIZE];
    let mut change = [[0; 32]; CHANGE_CACHE_SIZE];
    receive[3] = [3; 32];
    change[2] = [9; 32];
    (receive, change)
}

fn render_input<'a>(
    receive: &'a [[u8; 32]; RECEIVE_CACHE_SIZE],
    change: &'a [[u8; 32]; CHANGE_CACHE_SIZE],
) -> AddressRenderInput<'a> {
    AddressRenderInput {
        receive_cache: receive,
        change_cache: change,
        extra_receive: [7; 32],
        extra_receive_index: 25,
        extra_change: [8; 32],
        extra_change_index: 8,
        current_index: 3,
        is_change: false,
        raw_key: false,
        partial_redraw: true,
    }
}

#[test]
fn address_render_model_selects_cache_extra_and_raw_key_modes() {
    let (receive, change) = caches();
    let input = render_input(&receive, &change);
    assert_eq!(select_public_key(&input), Some([3; 32]));
    assert_eq!(
        select_public_key(&AddressRenderInput {
            current_index: 25,
            ..input
        }),
        Some([7; 32])
    );
    assert_eq!(
        select_public_key(&AddressRenderInput {
            current_index: 2,
            is_change: true,
            ..input
        }),
        Some([9; 32])
    );
    assert_eq!(
        select_public_key(&AddressRenderInput {
            current_index: 8,
            is_change: true,
            ..input
        }),
        Some([8; 32])
    );
    assert_eq!(
        select_public_key(&AddressRenderInput {
            current_index: 9,
            is_change: true,
            ..input
        }),
        None
    );
    let model = address_render_model(input).unwrap();
    assert_eq!(model.index, Some(3));
    assert!(model.partial_update);
    let raw = address_render_model(AddressRenderInput {
        raw_key: true,
        ..input
    })
    .unwrap();
    assert_eq!(raw.index, None);
    assert!(!raw.partial_update);

    let zero_receive = [[0u8; 32]; RECEIVE_CACHE_SIZE];
    assert_eq!(
        address_render_model(AddressRenderInput {
            receive_cache: &zero_receive,
            ..input
        }),
        None
    );
}

#[test]
fn wallet_word_count_titles_are_stable() {
    assert_eq!(word_count_title(0), "New Seed");
    assert_eq!(word_count_title(1), "New Seed (Dice)");
    assert_eq!(word_count_title(2), "Import Words");
    assert_eq!(word_count_title(3), "Calc Last Word");
    assert_eq!(word_count_title(4), "BIP85 Child");
    assert_eq!(word_count_title(5), "New Seed (Touch)");
    assert_eq!(word_count_title(9), "Choose");
}

#[test]
fn seed_qr_grid_clamps_each_axis_at_zero_and_maximum() {
    let zero = SeedQrGridState {
        pan_x: 0,
        pan_y: 0,
        compact: false,
    };
    assert_eq!(reduce_grid(zero, 29, 10, 60, false), SeedQrGridEffect::None);
    assert_eq!(
        reduce_grid(zero, 29, 300, 60, false),
        SeedQrGridEffect::None
    );
    let maximum = SeedQrGridState {
        pan_x: 22,
        pan_y: 22,
        compact: false,
    };
    assert_eq!(
        reduce_grid(maximum, 29, 10, 150, false),
        SeedQrGridEffect::None
    );
    assert_eq!(
        reduce_grid(maximum, 29, 300, 150, false),
        SeedQrGridEffect::None
    );
}

#[test]
fn worker_lifecycle_requires_ready_and_round_trips_one_result() {
    use crate::runtime::worker::{ReserveError, WorkerLifecycle};
    let worker = WorkerLifecycle::new();
    assert_eq!(worker.reserve(), Err(ReserveError::Unavailable));
    worker.mark_ready();
    let generation = worker.reserve().expect("ready worker reserves");
    assert!(worker.publish_ready(generation, 7));
    assert_eq!(worker.progress(generation), 7);
    assert!(worker.claim_ready());
    worker.set_progress(61);
    assert_eq!(worker.progress(generation), 61);
    assert!(worker.begin_publish(generation));
    assert!(worker.finish_publish());
    assert!(worker.claim_result(generation));
    worker.finish_result_take();
    assert!(worker.is_idle());
}

#[test]
fn worker_lifecycle_cancellation_covers_every_cross_core_race_boundary() {
    use crate::runtime::worker::{CancelAction, WorkerLifecycle};

    let queued = WorkerLifecycle::new();
    queued.mark_ready();
    let queued_generation = queued.reserve().expect("reserve queued");
    assert!(queued.publish_ready(queued_generation, 1));
    assert_eq!(
        queued.cancel(queued_generation),
        CancelAction::DropQueuedJob
    );
    queued.finish_cancelled();
    assert!(queued.is_idle());

    let busy = WorkerLifecycle::new();
    busy.mark_ready();
    let busy_generation = busy.reserve().expect("reserve busy");
    assert!(busy.publish_ready(busy_generation, 1));
    assert!(busy.claim_ready());
    assert_eq!(
        busy.cancel(busy_generation),
        CancelAction::WorkerWillDiscard
    );
    assert!(!busy.begin_publish(busy_generation));
    busy.finish_cancelled();
    assert!(busy.is_idle());

    let publishing = WorkerLifecycle::new();
    publishing.mark_ready();
    let publishing_generation = publishing.reserve().expect("reserve publishing");
    assert!(publishing.publish_ready(publishing_generation, 1));
    assert!(publishing.claim_ready());
    assert!(publishing.begin_publish(publishing_generation));
    assert_eq!(
        publishing.cancel(publishing_generation),
        CancelAction::WorkerWillDiscard
    );
    assert!(!publishing.finish_publish());
    publishing.finish_cancelled();
    assert!(publishing.is_idle());

    let completed = WorkerLifecycle::new();
    completed.mark_ready();
    let completed_generation = completed.reserve().expect("reserve completed");
    assert!(completed.publish_ready(completed_generation, 1));
    assert!(completed.claim_ready());
    assert!(completed.begin_publish(completed_generation));
    assert!(completed.finish_publish());
    assert_eq!(
        completed.cancel(completed_generation),
        CancelAction::DropCompletedResult
    );
    completed.finish_cancelled();
    assert!(completed.is_idle());
}

#[test]
fn worker_lifecycle_stale_generation_cannot_cancel_new_work() {
    use crate::runtime::worker::{CancelAction, WorkerLifecycle};
    let worker = WorkerLifecycle::new();
    worker.mark_ready();
    let old = worker.reserve().expect("reserve first");
    assert!(worker.publish_ready(old, 1));
    assert_eq!(worker.cancel(old), CancelAction::DropQueuedJob);
    worker.finish_cancelled();
    let current = worker.reserve().expect("reserve second");
    assert_ne!(old, current);
    assert!(worker.publish_ready(current, 2));
    assert_eq!(worker.cancel(old), CancelAction::None);
    assert_eq!(worker.progress(current), 2);
}
