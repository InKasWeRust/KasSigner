#!/usr/bin/env python3
"""Regression contracts for the direct-KasSee mobile shells and web quality scope."""
from __future__ import annotations
import importlib.util
from pathlib import Path
import sys, unittest
ROOT = Path(__file__).resolve().parents[3]

def load(path: Path, name: str):
    spec=importlib.util.spec_from_file_location(name,path); assert spec and spec.loader
    module=importlib.util.module_from_spec(spec); sys.modules[name]=module; spec.loader.exec_module(module); return module

class MobileWebCoverageContracts(unittest.TestCase):
    def test_android_mutation_scope_covers_live_domain_and_infrastructure(self):
        path=ROOT/'qa/checks/android/run_mutation_tests.py'; source=path.read_text(); self.assertNotIn('MUTANTS =',source)
        module=load(path,'android_full_mutation'); mutants,files=module.discover()
        relative=[f.relative_to(module.SOURCE).as_posix() for f in files]
        self.assertTrue(any(x.startswith('domain/') for x in relative)); self.assertTrue(any(x.startswith('infrastructure/') for x in relative))
        self.assertEqual(set(relative),{p.relative_to(module.SOURCE).as_posix() for r in module.SCOPE_ROOTS for p in r.rglob('*.kt')})
        self.assertGreater(len(mutants),0); self.assertEqual(module.MINIMUM_SCORE_PERCENT,100.0)

    def test_ios_mutation_scope_covers_live_security_weather_native_code(self):
        path=ROOT/'qa/checks/ios/run_mutation_tests.py'; source=path.read_text(); self.assertNotIn('MUTANTS =',source)
        module=load(path,'ios_full_mutation'); mutants,files=module.discover()
        relative=[f.relative_to(module.SOURCE).as_posix() for f in files]
        self.assertTrue(any(x.startswith('Features/Cover/Components/') for x in relative)); self.assertTrue(any(x.startswith('Infrastructure/') for x in relative))
        self.assertEqual(set(relative),{p.relative_to(module.SOURCE).as_posix() for r in module.SCOPE_ROOTS for p in r.rglob('*.swift')})
        self.assertGreater(len(mutants),0); self.assertEqual(module.MINIMUM_SCORE_PERCENT,100.0)
        self.assertIn('-only-testing:KasSignerAppTests', source)
        self.assertIn('DERIVED_DATA = ROOT / "target/ios/DerivedData"', source)
        self.assertIn('"-derivedDataPath", str(DERIVED_DATA)', source)
        self.assertIn('KASSIGNER_IOS_RUNTIME_SYNCED=1', source)
        self.assertIn('runtime = prepare_runtime()', source)
        self.assertIn('xcode_unit_tests(timeout=BASELINE_TIMEOUT_SECONDS)', source)
        self.assertIn('xcode_unit_tests(timeout=MUTANT_TIMEOUT_SECONDS, stop_on_verdict=True)', source)
        self.assertIn('mutant was not counted as killed', source)
        project=(ROOT/'apps/kassee-ios/KasSigner.xcodeproj/project.pbxproj').read_text()
        self.assertIn('KASSIGNER_IOS_RUNTIME_SYNCED:-0', project)
        self.assertIn('shared KasSee runtime already synchronized; skipping regeneration', project)
        self.assertIn('stop_on_verdict=True', source)
        self.assertIn('accepted completed XCTest aggregate verdict', source)

        failed = """Test Suite 'All tests' failed at 2026-09-04 21:21:19.627.
	 Executed 20 tests, with 2 failures (0 unexpected) in 1.412 seconds
"""
        passed = """Test Suite 'All tests' passed at 2026-09-04 21:21:19.627.
	 Executed 20 tests, with 0 failures (0 unexpected) in 1.412 seconds
"""
        zero = """Test Suite 'All tests' failed at 2026-09-04 21:21:19.627.
	 Executed 0 tests, with 1 failure (0 unexpected) in 1.412 seconds
"""
        self.assertIs(module.xctest_verdict(failed), False)
        self.assertIs(module.xctest_verdict(passed), True)
        self.assertIsNone(module.xctest_verdict(zero))
        self.assertIsNone(module.xctest_verdict('BUILD FAILED before tests ran'))

    def test_mobile_shell_tests_are_nonempty_and_legacy_wallet_tests_are_absent(self):
        android=ROOT/'apps/kassee-android/app/src'
        unit=list((android/'test').rglob('*Test.kt')); instrumented=list((android/'androidTest').rglob('*Test.kt'))
        self.assertGreaterEqual(len(unit),2); self.assertGreaterEqual(len(instrumented),1)
        combined='\n'.join(p.read_text() for p in unit+instrumented)
        self.assertIn('WeatherUnlockPolicy',combined); self.assertIn('ActivityScenario',combined)
        for marker in ('PendingSigningStore','TransactionPayloadIO','NativeBridge','WalletNetwork.TESTNET'):
            self.assertNotIn(marker,combined)
        ios=ROOT/'apps/kassee-ios'
        self.assertFalse((ios/'Tests/KasSignerCoreTests').exists()); self.assertFalse((ios/'Package.swift').exists())


    def test_mobile_shells_package_the_complete_current_kassee_ui(self):
        android_host=(ROOT/'apps/kassee-android/app/src/main/java/org/kassigner/kassigner/app/KasSeeWebViewHost.kt').read_text()
        android_build=(ROOT/'apps/kassee-android/app/build.gradle.kts').read_text()
        self.assertIn('assets/kassee/index.html',android_host)
        self.assertIn('into("kassee")',android_build); self.assertIn('canonicalKasSeeSite',android_build)
        self.assertIn('addGeneratedSourceDirectory(',android_build)
        self.assertIn('build_kassee_runtime.py',android_build); self.assertNotIn('"bash", "-lc"',android_build)
        ios_server=(ROOT/'apps/kassee-ios/KasSigner/Features/Root/Components/KasSeeLoopbackServer.swift').read_text()
        ios_sync=(ROOT/'tools/build/ios/sync_runtime.py').read_text()
        self.assertIn('KasSeeUI',ios_server)
        self.assertIn('normalizedRequestPath',ios_server)
        self.assertIn('httpResponseHeader',ios_server)
        self.assertIn('joined(separator: "\\r\\n")',ios_server)
        self.assertIn('contentContext: .finalMessage',ios_server)
        self.assertIn('isComplete: true',ios_server)
        self.assertIn('shutil.copytree',ios_sync); self.assertIn('kassee_web_bg.wasm',ios_sync)


    def test_mobile_hosts_are_split_and_share_one_adaptation_module(self):
        android=ROOT/'apps/kassee-android/app/src/main/java/org/kassigner/kassigner/app'
        main=(android/'MainActivity.kt').read_text(); host=(android/'KasSeeWebViewHost.kt').read_text()
        bridge=(android/'KasSeeMobileBridge.kt').read_text()
        self.assertLessEqual(len(main.splitlines()),200); self.assertLessEqual(len(host.splitlines()),400)
        self.assertIn('KasSeeWebViewHost(',main); self.assertIn('@JavascriptInterface',bridge)
        ios=ROOT/'apps/kassee-ios/KasSigner/Features/Root/Components'
        self.assertLessEqual(len((ios/'RootView.swift').read_text().splitlines()),100)
        self.assertLessEqual(len((ios/'KasSeeWebView.swift').read_text().splitlines()),200)
        self.assertLessEqual(len((ios/'KasSeeLoopbackServer.swift').read_text().splitlines()),200)
        adaptation=(ROOT/'apps/kassee-web/web/js/mobile/native_adaptations.js').read_text()
        self.assertIn('installMobileAdaptations',adaptation)
        for native in (host,(ios/'KasSeeWebView.swift').read_text()):
            self.assertIn("import('./js/mobile/native_adaptations.js')",native)
            self.assertNotIn('kassigner-mobile-empty-import .kpub-manager-list-card',native)

    def test_wallet_cleanup_stops_long_lived_runtime_watchers(self):
        reset=(ROOT/'apps/kassee-web/web/js/features/wallet/state_reset.js').read_text()
        for stop in ('stopOracleMbCountdown()', 'stopCrowdfundWatcher()', 'stopPrivateSwapWatcher()'):
            self.assertIn(stop,reset)
        countdown=(ROOT/'apps/kassee-web/web/js/features/oracle/model_b/controller/proving/countdown.js').read_text()
        self.assertIn('export function stopOracleMbCountdown()',countdown)
        crowd=(ROOT/'apps/kassee-web/web/js/features/covenants/crowdfund/sweep.js').read_text()
        self.assertIn('export function stopCrowdfundWatcher()',crowd)

    def test_camera_qr_decode_is_throttled_without_per_frame_canvas_resize(self):
        camera=(ROOT/'apps/kassee-web/web/js/features/stealth/index/camera.js').read_text()
        self.assertIn('SCAN_INTERVAL_MS = 80',camera)
        self.assertIn('now - lastDecodeAt >= SCAN_INTERVAL_MS',camera)
        self.assertIn('canvas.width !== video.videoWidth || canvas.height !== video.videoHeight',camera)
        self.assertIn('requestAnimationFrame(timestamp => scanLoop',camera)
        self.assertIn('let scannerGeneration = 0',camera)
        self.assertIn('const generation = ++scannerGeneration',camera)
        self.assertIn('if (generation !== scannerGeneration)',camera)
        self.assertIn('++scannerGeneration',camera)

    def test_android_runtime_builder_is_cross_platform_and_studio_scripts_are_canonical(self):
        gradle=(ROOT/'apps/kassee-android/app/build.gradle.kts').read_text()
        self.assertIn('build_kassee_runtime.py',gradle); self.assertNotIn('"bash", "-lc"',gradle)
        self.assertFalse((ROOT/'apps/kassee-android/start-android-studio.sh').exists())
        self.assertFalse((ROOT/'apps/kassee-android/start-android-studio.ps1').exists())
        linux=(ROOT/'scripts/linux/build/android-studio.sh').read_text()
        windows=(ROOT/'scripts/windows/build/android-studio.ps1').read_text()
        self.assertIn('ANDROID_DIR="$REPO_ROOT/apps/kassee-android"',linux)
        self.assertIn("$android = Join-Path $root 'apps/kassee-android'",windows)
        self.assertNotIn('../lib/_invoke.sh',linux); self.assertNotIn('../lib/_invoke.ps1',windows)

    def test_web_runtime_collector_maps_the_real_main_module_graph(self):
        path=ROOT/'qa/checks/web/run_web_runtime_coverage.py'; module=load(path,'web_runtime_coverage')
        reachable=module.reachable_modules(); all_js={p.relative_to(ROOT).as_posix() for p in (ROOT/'apps/kassee-web/web/js').rglob('*.js')}
        self.assertEqual(reachable,all_js); self.assertEqual(len(reachable),320)
        runtime_test=(ROOT/'qa/checks/web/check_web_runtime.mjs').read_text(); self.assertIn('runtime-coverage-entry=1',runtime_test)

if __name__=='__main__': unittest.main()
