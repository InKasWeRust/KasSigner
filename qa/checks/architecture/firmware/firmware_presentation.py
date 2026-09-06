"""Firmware presentation and unified-operation architecture boundaries."""

from pathlib import Path


def check(root: Path) -> list[str]:
    errors: list[str] = []
    firmware = root / "apps/signer-firmware/src"
    state = _read(firmware / "runtime/input/state.rs")
    graph_states = _read(firmware / "runtime/navigation/ui_graph/states.rs")
    graph_menus = _read(firmware / "runtime/navigation/ui_graph/menus.rs")
    presentation_data = _read(firmware / "runtime/data/presentation/mod.rs")
    operation_state = _read(firmware / "runtime/data/presentation/operation.rs")
    operation_kind = _read(firmware / "runtime/data/presentation/kind.rs")
    presentation = _read(firmware / "runtime/presentation/mod.rs")
    event_loop = _read(firmware / "runtime/event_loop/mod.rs")
    operation_engine = _read(firmware / "runtime/event_loop/operation_engine/mod.rs")
    credential_driver = "\n".join(_read(path) for path in (firmware / "runtime/event_loop/operation_engine/credential").glob("*.rs"))
    credential_interaction = _read(firmware / "runtime/interactions/persistence/credential.rs")
    kpub_driver = _read(firmware / "runtime/event_loop/runner/deferred/kpub.rs")
    signing_driver = _read(firmware / "runtime/signing/workflow.rs")
    presentation_redraw = _read(firmware / "ui/redraw/presentation/mod.rs")
    workflow_signing_adapter = _read(firmware / "runtime/signing/workflow_test.rs")
    workflow_signing_result = _read(firmware / "runtime/workflow_tests/connected/signing/result.rs")
    redraw = _read(firmware / "ui/redraw.rs")

    for retired in ("ConnectKasSeeLoading", "MultisigKpubLoading", "Signing { input_idx"):
        if retired in state or retired in graph_states:
            errors.append(f"long-running operation remains encoded as stable AppState: {retired}")

    for token in ("pub enum OperationKind", "enum OperationExecution", "pub enum OperationPhase", "pub enum ModalState", "pub struct PresentationState"):
        if token not in operation_kind + operation_state + presentation_data:
            errors.append(f"presentation architecture is missing {token}")
    for phase in ("Queued", "Presented", "Running", "Progress"):
        if phase not in operation_state:
            errors.append(f"unified operation lifecycle is missing {phase}")
    retired_credential_machine = firmware / "runtime/data/presentation/credential.rs"
    if retired_credential_machine.exists() or "credential:" in presentation_data:
        errors.append("credential flow must not own a second presentation state machine")

    for operation in ("ConnectKasSee", "DeriveMultisigKpub", "SignTransaction"):
        if operation not in graph_menus:
            errors.append(f"production UI graph is missing operation effect: {operation}")

    if "presentation::redraw(ad, boot_display)" not in redraw:
        errors.append("operation/modal presentation must render before the stable AppState screen")
    if "if ad.presentation.operation.phase() == OperationPhase::Queued" not in presentation_redraw:
        errors.append("operation redraw must mark Presented only from the one-shot Queued phase")
    if presentation_redraw.count("mark_operation_presented(ad)") != 1:
        errors.append("operation redraw must own exactly one guarded Presented transition call site")
    for token in (
        "OperationPhase::Running | OperationPhase::Progress(_)",
        "presentation::set_progress(ad, progress.min(100) as u8)",
        "workflow_activate_signing_operation",
    ):
        if token not in workflow_signing_adapter:
            errors.append(f"workflow signing lifecycle parity is missing {token}")
    for token in (
        "OperationPhase::Progress(50)",
        "ctx.redraw();",
        "SIGN TX LIFECYCLE PROGRESS-REDRAW 1/2 PASS",
    ):
        if token not in workflow_signing_result:
            errors.append(f"two-input signing lifecycle redraw regression is missing {token}")
    priority_pos = event_loop.find("navigation_dispatch::render_priority_operation")
    engine_pos = event_loop.rfind("operation_engine::service")
    if priority_pos < 0 or engine_pos < 0 or priority_pos >= engine_pos:
        errors.append("operation surface must be physically rendered before the operation engine executes")
    exclusive_guard_pos = event_loop.find("operation_engine::owns_exclusive_frame(&operation_engine)")
    first_hardware_pos = event_loop.find("event_loop::audio::service")
    if exclusive_guard_pos < 0 or first_hardware_pos < 0 or exclusive_guard_pos >= first_hardware_pos:
        errors.append("foreground-exclusive operation guard must run before ordinary hardware service")

    # One lifecycle owner: only the operation engine may cross Presented -> Running.
    if operation_engine.count("take_ready_operation(ad)") != 1:
        errors.append("operation engine must be the single Presented-to-Running transition owner")
    for name, source in (("kpub", kpub_driver), ("signing", signing_driver), ("credential", credential_driver)):
        if "take_ready_operation(" in source:
            errors.append(f"{name} driver starts its own operation instead of using the unified engine")
    for kind in (
        "SaveWalletPin", "SaveWalletPassword", "UnlockWalletPin", "UnlockWalletPassword",
        "ConnectKasSee", "DeriveMultisigKpub", "SignTransaction",
    ):
        if f"OperationKind::{kind}" not in operation_engine:
            errors.append(f"unified operation engine does not dispatch {kind}")
    for token in ("ForegroundExclusive", "Stepped", "execution(self)", "kind.stepped()", "fn asynchronous"):
        if token not in operation_kind + operation_engine:
            errors.append(f"operation execution policy is missing {token}")

    # Controllers/interactions queue work only; persistence/KDF lives in the operation driver.
    for forbidden in ("save_with_credential(", "unlock_saved("):
        if forbidden in credential_interaction:
            errors.append(f"credential input interaction performs blocking persistence work: {forbidden}")
        # Foreground-exclusive credentials still use split begin/finish persistence rather than legacy blocking APIs.
        if forbidden in credential_driver:
            errors.append(f"credential driver must not call legacy blocking persistence API: {forbidden}")

    for token in (
        "start_credential_operation", "mark_operation_presented", "take_ready_operation",
        "execution_done", "credential_result_committed", "OP-ORDER-01",
    ):
        if token not in presentation + operation_engine + credential_driver:
            errors.append(f"unified credential lifecycle is missing {token}")
    for token in ("owns_exclusive_frame", "ForegroundExclusive", "Credential foreground-exclusive lane ARMED"):
        if token not in credential_driver + operation_engine + event_loop + operation_kind:
            errors.append(f"credential foreground-exclusive lane is missing {token}")
    for marker in (
        "KASSIGNER_PIN_FLOW: PIN SUBMIT",
        "KASSIGNER_PIN_FLOW: LOADING COMMITTED",
        "KASSIGNER_PIN_FLOW: LOADING RENDERED",
        "KASSIGNER_PIN_FLOW: KDF BEGIN",
        "KASSIGNER_PIN_FLOW: KDF DONE",
        "KASSIGNER_PIN_FLOW: RESULT COMMITTED",
    ):
        if marker not in presentation:
            errors.append(f"credential operation ordering marker is missing: {marker}")

    password_kdf = _read(firmware / "services/memory/password_kdf.rs")
    shared_core = _read(firmware / "hw/shared/core.rs")
    for forbidden in ("with_primary_core_exclusive", "park_core", "unpark_core", "CPU_CTRL::steal"):
        if forbidden in password_kdf:
            errors.append(f"foreground Argon2 must not hard-stall the peer core: {forbidden}")
    for token in ("derive_key_32_foreground", "Argon2 PSRAM foreground BEGIN", "Argon2 PSRAM foreground DONE"):
        if token not in password_kdf:
            errors.append(f"foreground Argon2 adapter is missing {token}")
    for token in ("with_other_core_parked", "park_core", "unpark_core"):
        if token not in shared_core:
            errors.append(f"flash-only peer-core coordination is missing {token}")
    for retired in ("credential_kdf_worker", "process_if_ready()", "WorkerDriven"):
        if retired in credential_driver + operation_engine + event_loop:
            errors.append(f"retired credential Core1 worker path remains reachable: {retired}")

    errors.extend(_check_error_and_reset_boundaries(root, firmware, presentation, credential_driver))
    errors.extend(_check_liveness(root, firmware, operation_state + operation_kind, presentation, operation_engine))
    errors.extend(_check_hardware_evidence(root, firmware))
    return errors


def _check_error_and_reset_boundaries(root: Path, firmware: Path, presentation: str, credential_driver: str) -> list[str]:
    errors: list[str] = []
    error_catalog = _read(firmware / "runtime/presentation/errors.rs")
    camera_cycle = _read(firmware / "runtime/interactions/camera_loop/cycle.rs")
    signing = _read(firmware / "runtime/signing/workflow.rs")
    qr = _read(firmware / "runtime/signing/qr.rs")
    frame = _read(firmware / "runtime/event_loop/frame.rs")
    persistence = _read(firmware / "runtime/event_loop/persistence.rs")
    nav_kernel = _read(firmware / "runtime/navigation/kernel.rs")
    protocol_paths = (
        firmware / "runtime/interactions/tx/transaction.rs",
        firmware / "runtime/interactions/camera_loop/dispatch/covenant_sign.rs",
        firmware / "runtime/interactions/camera_loop/dispatch/private_swap.rs",
    )
    for code in ("CAM-01", "SD-WRITE-01", "STORE-SYNC-01", "QR-FRAME-01", "SIGN-INPUT-01", "UI-NAV-01"):
        if code not in error_catalog:
            errors.append(f"recoverable error catalog is missing {code}")
    if "previous_stable_screen(ad)" not in camera_cycle or "show_error_spec_to" not in camera_cycle:
        errors.append("camera faults must use a recoverable modal and bounded stable-screen target")
    if "draw_camera_fault_screen" in camera_cycle:
        errors.append("camera interaction adapter must not own an ad-hoc fault screen")
    if "draw_rejected_screen" in signing:
        errors.append("transaction signing failures must use recoverable presentation")
    for token in ("SIGN_ENTROPY", "SIGN_INPUT", "SIGN_KEY", "SIGN_POLICY", "SIGN_REVIEW"):
        if token not in signing:
            errors.append(f"transaction signing failure is missing diagnostic category {token}")
    if "draw_rejected_screen" in qr or "QR_FRAME" not in qr:
        errors.append("QR frame failure must use the recoverable QR_FRAME modal")
    if "draw_rejected_screen" in frame or "SD_WRITE" not in frame:
        errors.append("post-frame SD write failure must use the recoverable SD_WRITE modal")
    if "draw_rejected_screen" in persistence or "STORAGE_SYNC" not in persistence or "POLICY_SAVE" not in persistence:
        errors.append("wallet/policy persistence failures must use recoverable presentation")
    for path in protocol_paths:
        if "draw_tx_error_screen" in _read(path):
            errors.append(f"protocol adapter owns an ad-hoc error screen: {path.relative_to(root)}")
    if "return_from_error" not in presentation or "HistoryEffect::PopTo(target)" not in nav_kernel:
        errors.append("recoverable modal OK must return through bounded navigation history")
    if "presentation::NAVIGATION" not in nav_kernel:
        errors.append("navigation recovery must surface a recoverable diagnostic modal")
    layout = _read(firmware / "ui/layout.rs")
    if "ERROR_OK_ZONE" not in layout or "ERROR_OK_ZONE.contains(x, y)" not in presentation:
        errors.append("recoverable errors must share the rendered OK-dismiss geometry")
    if "software_reset" in presentation:
        errors.append("presentation layer must never reset the MCU")
    if credential_driver.count("software_reset()") != 1 or "PersistError::DuressTriggered" not in credential_driver:
        errors.append("only the explicitly classified duress credential path may software-reset")
    reset_paths = sorted(
        path.relative_to(firmware).as_posix()
        for path in firmware.rglob("*.rs")
        if "software_reset" in _read(path)
    )
    allowed = sorted([
        "runtime/event_loop/operation_engine/credential/result.rs",
        "runtime/interactions/settings/advanced/factory_reset.rs",
        "runtime/interactions/settings/advanced/pop_it.rs",
        "runtime/interactions/settings/advanced/owner_firmware.rs",
    ])
    if reset_paths != allowed:
        errors.append(f"software reset is not limited to explicit duress/factory-reset/Pop It paths: {reset_paths}")
    return errors


def _check_liveness(root: Path, firmware: Path, operation_meta: str, presentation: str, operation_engine: str) -> list[str]:
    errors: list[str] = []
    address_cache = _read(firmware / "runtime/event_loop/runner/deferred/address_cache.rs")
    core_s3 = _read(firmware / "runtime/core_s3.rs")
    error_catalog = _read(firmware / "runtime/presentation/errors.rs")
    for token in ("total_budget_ms", "stall_budget_ms", "20_000", "timed_out"):
        if token not in operation_meta:
            errors.append(f"bounded operation liveness metadata is missing {token}")
    for token in ("timed_out_operation", "timeout_operation", "fail_recoverable_spec"):
        if token not in presentation + operation_engine:
            errors.append(f"pre-watchdog operation recovery is missing {token}")
    for token in ("ADDRESS_TOTAL_BUDGET_MS", "ADDRESS_STALL_BUDGET_MS", "timeout_if_stalled", "ADDRESS_TIMEOUT"):
        if token not in address_cache:
            errors.append(f"Receive/Change pre-watchdog recovery is missing {token}")
    for code in ("OP-TIMEOUT-01", "OP-TIMEOUT-02", "OP-TIMEOUT-03", "OP-TIMEOUT-04"):
        if code not in error_catalog:
            errors.append(f"timeout diagnostic catalog is missing {code}")
    for token in ("DEFAULT_WATCHDOG_MS", "30_000", "CREDENTIAL_WATCHDOG_MS", "90_000", "watchdog.feed()"):
        if token not in core_s3:
            errors.append(f"CoreS3 watchdog policy is missing {token}")
    return errors


def _check_hardware_evidence(root: Path, firmware: Path) -> list[str]:
    errors: list[str] = []
    workflow_runtime = _read(firmware / "runtime/workflow_tests/connected/runtime_gui.rs")
    credential_hil = _read(firmware / "runtime/workflow_tests/connected/onboarding/credentials.rs")
    workflow_host = _read(root / "qa/checks/firmware/run_workflow_tests.py")
    hardware_host = _read(root / "qa/checks/firmware/run_hardware_tests.py")
    for action in ("pin-unlock-loading-order", "connect-kassee-real-derivation"):
        if action not in workflow_runtime:
            errors.append(f"CoreS3 runtime HIL is missing {action}")
    if "persistent-pin-storage-round-trip" not in credential_hil:
        errors.append("CoreS3 HIL must execute a real persistent PIN storage/unlock round-trip")
    if "PIN_FLOW_ORDERED_MARKERS" not in workflow_host or "ordered_markers=" not in workflow_host:
        errors.append("workflow HIL must enforce PIN lifecycle ordering evidence")
    if "runtime evidence arrived out of order" not in hardware_host:
        errors.append("hardware supervisor must fail closed on out-of-order runtime evidence")
    return errors


def _read(path: Path) -> str:
    return path.read_text(errors="ignore") if path.exists() else ""
