from pathlib import Path
import json
import unittest

ROOT = Path(__file__).resolve().parents[3]
FW = ROOT / "apps/signer-firmware"


class WalletInventoryBehaviorTests(unittest.TestCase):
    def test_connected_inventory_uses_canonical_add_first_row_order(self):
        wallet = (FW / "src/runtime/workflow_tests/connected/wallet.rs").read_text()
        inventory = wallet.split("fn wallet_inventory", 1)[1].split("fn add_wallet_routes", 1)[0]
        self.assertIn("ctx.seed_list_touch(160, 158, false)", inventory)
        self.assertIn("seed_mgr.active != 1", inventory)
        self.assertNotIn("ctx.seed_list_touch(160, 112, false)", inventory)
        self.assertIn("Add Wallet first, then loaded wallets", inventory)

    def test_add_wallet_probe_selects_item_zero_without_paging_away(self):
        wallet = (FW / "src/runtime/workflow_tests/connected/wallet.rs").read_text()
        open_add = wallet.split("fn open_add_wallet_menu", 1)[1].split("fn exercise_add_wallet_create", 1)[0]
        self.assertIn("ctx.seed_list_touch(160, 66, false)", open_add)
        self.assertNotIn("seed_list_touch(300, 112, false)", open_add)
        self.assertNotIn("seed_list_scroll != 3", open_add)
        self.assertIn("AppState::AddWalletChoice", open_add)

    def test_production_inventory_and_renderer_agree_add_wallet_is_item_zero(self):
        controller = (FW / "src/runtime/interactions/seed/seed_list/list.rs").read_text()
        renderer = (FW / "src/ui/screens/wallet/seed_slots.rs").read_text()
        self.assertIn("if can_add && item == 0", controller)
        self.assertIn("if can_add && list_index == 0", renderer)
        self.assertIn("item.saturating_sub(usize::from(can_add))", controller)
        self.assertIn("list_index.saturating_sub(usize::from(can_add))", renderer)

    def test_inventory_failures_replay_specific_substage(self):
        wallet = (FW / "src/runtime/workflow_tests/connected/wallet.rs").read_text()
        for stage, label in (
            (40, "INVENTORY-PAGE-DOWN"),
            (41, "INVENTORY-PAGE-UP"),
            (42, "INVENTORY-ACTIVATE"),
            (43, "INVENTORY-RETURN"),
        ):
            self.assertIn(f"mark_failure_stage({stage})", wallet)
            self.assertIn(label, wallet)



if __name__ == "__main__":
    unittest.main()
