#!/usr/bin/env python3
"""Preserves durable connected failure evidence and QA registration."""
from pathlib import Path
import json
import unittest
ROOT=Path(__file__).resolve().parents[3]
class ConnectedFailureRecoveryTests(unittest.TestCase):
    def test_probe_status_module_doc_precedes_imports(self):
        helper=(ROOT/'apps/signer-firmware/src/runtime/workflow_tests/connected/probe_status.rs').read_text()
        first_nonblank=next(line for line in helper.splitlines() if line.strip())
        self.assertEqual(first_nonblank, '//! Generic connected-E2E subprobe accounting and liveness checkpoints.')
        self.assertLess(helper.index('//! Generic connected-E2E'), helper.index('use core::sync::atomic'))
    def test_scenario_recovery_uses_authoritative_reset(self):
        anti=(ROOT/'apps/signer-firmware/src/runtime/workflow_tests/connected/signing/anti_klepto.rs').read_text()
        recover=anti.split('fn recover',1)[1].split('fn request_wire',1)[0]
        self.assertIn('reset_tranche_to_home',recover); self.assertNotIn('effects::home',recover)
        backup=(ROOT/'apps/signer-firmware/src/runtime/workflow_tests/connected/backup.rs').read_text()
        entry=backup.split('pub(super) fn enter_advanced_backup',1)[1].split('pub(super) struct WorkflowBackupDevice',1)[0]
        self.assertIn('reset_tranche_to_home',entry); self.assertNotIn('effects::home',entry)
    def test_four_failed_tranches_have_tail_replay(self):
        connected=(ROOT/'apps/signer-firmware/src/runtime/workflow_tests/connected/mod.rs').read_text()
        self.assertIn('probe_status::replay_mask', connected)
        for scope in ('ROOT','ONBOARDING','SIGNING','SD-WORKFLOWS'):
            self.assertIn(f'\"{scope}\"', connected)
        helper=(ROOT/'apps/signer-firmware/src/runtime/workflow_tests/connected/probe_status.rs').read_text()
        self.assertIn('pub(super) fn replay_mask', helper)
        for rel in ('root.rs','onboarding/mod.rs','signing/mod.rs','sd_workflows/mod.rs'):
            text=(ROOT/'apps/signer-firmware/src/runtime/workflow_tests/connected'/rel).read_text()
            self.assertIn('pub(super) static FAILURE_MASK',text)
if __name__=='__main__': unittest.main()
