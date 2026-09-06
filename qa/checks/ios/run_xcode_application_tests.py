#!/usr/bin/env python3
"""Run actual KasSigner app XCTest/XCUITest targets on a macOS Xcode host."""
from __future__ import annotations
import os, platform, shutil, subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[3]
PROJECT=ROOT/'apps/kassee-ios/KasSigner.xcodeproj'

def main()->int:
    if platform.system()!='Darwin' or shutil.which('xcodebuild') is None:
        print('SKIP: iOS application XCTest/XCUITest requires a macOS host with Xcode (not counted as PASS).')
        return 0
    destination=os.environ.get('KASSIGNER_IOS_TEST_DESTINATION','platform=iOS Simulator,name=iPhone 16 Pro')
    cmd=['xcodebuild','-project',str(PROJECT),'-scheme','KasSigner','-configuration','Debug','-destination',destination,'test']
    print('  +',' '.join(cmd),flush=True)
    return subprocess.run(cmd,cwd=ROOT).returncode
if __name__=='__main__': raise SystemExit(main())
