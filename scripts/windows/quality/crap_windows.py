#!/usr/bin/env python3
"""Native Windows CRAP/coverage pipeline equivalent to scripts/linux/quality/crap.sh."""
from __future__ import annotations
import argparse, json, os, shutil, subprocess, sys, tempfile
from datetime import datetime, timezone
from pathlib import Path
ROOT=Path(__file__).resolve().parents[3]
PY=sys.executable

def utc(): return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
def truthy(v): return str(v).lower() in {'1','true','yes'}
def run(cmd,cwd=ROOT,env=None,log=None,append=False,check=True):
    merged=os.environ.copy(); merged.update(env or {})
    if log:
        mode='a' if append else 'w'
        with open(log,mode,encoding='utf-8',errors='replace') as out:
            p=subprocess.Popen(cmd,cwd=cwd,env=merged,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,errors='replace')
            assert p.stdout
            for line in p.stdout: print(line,end=''); out.write(line)
            code=p.wait()
    else: code=subprocess.run(cmd,cwd=cwd,env=merged,check=False).returncode
    if check and code: raise subprocess.CalledProcessError(code,cmd)
    return code

def capture(cmd,cwd=ROOT,env=None): return subprocess.run(cmd,cwd=cwd,env={**os.environ,**(env or {})},text=True,capture_output=True,check=False)
def nonempty(p,label):
    if not p.is_file() or p.stat().st_size==0: raise RuntimeError(f'{label} was not generated or is empty: {p}')
def source_label():
    r=capture(['git','-C',str(ROOT),'rev-parse','--short','HEAD']) if shutil.which('git') else None
    return f"git {r.stdout.strip()} generated {utc()}" if r and r.returncode==0 else f"working tree generated {utc()}"

def main(argv):
    ap=argparse.ArgumentParser();ap.add_argument('--input-report',default='');ap.add_argument('--strict',action='store_true');ns=ap.parse_args(argv)
    output=Path(os.getenv('CRAP_OUTPUT_DIR',ROOT/'target/qa/crap')); ratchet=Path(os.getenv('CRAP_RATCHET_PATH',ROOT/'qa/contracts/quality/crap_ratchets.json'))
    dev=os.getenv('CRAP_DEV_OPT_LEVEL','0');test=os.getenv('CRAP_TEST_OPT_LEVEL','0'); toolchain=os.getenv('CRAP_COVERAGE_TOOLCHAIN','stable'); branch=truthy(os.getenv('CRAP_ENABLE_BRANCH','0'))
    if branch: toolchain=os.getenv('CRAP_BRANCH_TOOLCHAIN','')
    input_report=Path(ns.input_report) if ns.input_report else None
    missing=[]
    if branch and not toolchain: missing.append('CRAP_BRANCH_TOOLCHAIN (a pinned nightly toolchain)')
    for c in ('cargo','rustup','node'):
        if not shutil.which(c):missing.append(c)
    rustc=llvm=crap=''
    if not missing:
        r=capture(['rustup','run',toolchain,'rustc','--version']); rustc=r.stdout.strip();
        if r.returncode:missing.append(f'Rust toolchain {toolchain}')
    if not missing:
        r=capture(['cargo',f'+{toolchain}','llvm-cov','--version']); llvm=r.stdout.strip();
        if r.returncode:missing.append(f'cargo llvm-cov for {toolchain}')
        r=capture(['cargo',f'+{toolchain}','crap','--version']); crap=r.stdout.strip();
        if r.returncode:missing.append(f'cargo crap for {toolchain}')
        r=capture(['rustup','component','list','--toolchain',toolchain,'--installed']);
        if not any(x.startswith('llvm-tools') for x in r.stdout.splitlines()):missing.append(f'llvm-tools-preview for {toolchain}')
    if branch and toolchain and not toolchain.startswith('nightly'):missing.append('a pinned nightly toolchain for branch coverage')
    generation_ok=not missing
    if generation_ok:
        print(f'\nCRAP analysis tools detected:\n  Toolchain:      {toolchain}\n  Rust:           {rustc}\n  cargo llvm-cov: {llvm}\n  cargo crap:     {crap}\n  Branch data:    {"requested" if branch else "not requested"}\n')
    elif branch and not input_report:
        print('\nERROR: requested branch coverage could not run.\nThe pinned branch-coverage prerequisites are incomplete:',file=sys.stderr);[print(f'  - {x}',file=sys.stderr) for x in missing];print('Run `scripts/windows/quality/branch-coverage-setup.ps1`, then retry the strict QA pipeline.',file=sys.stderr);return 2
    elif not input_report:
        print('\nCRAP report generation skipped.\nThe optional local coverage tools are not fully available:');[print(f'  - {x}') for x in missing]
        return subprocess.run([PY,'qa/checks/quality/crap/check.py','--ignore-generated-report','--ratchet-contract',str(ratchet)],cwd=ROOT).returncode
    if input_report and not input_report.is_file(): print(f'ERROR: CRAP input report does not exist: {input_report}',file=sys.stderr);return 2
    previous=(output/'current.json').read_bytes() if (output/'current.json').is_file() else None; previous_run=(output/'run.json').read_bytes() if (output/'run.json').is_file() else None; previous_health=(output/'health_summary.json').read_bytes() if (output/'health_summary.json').is_file() else None
    shutil.rmtree(output,ignore_errors=True); output.mkdir(parents=True)
    if previous is not None:(output/'previous.json').write_bytes(previous)
    if previous_run is not None:(output/'previous_run.json').write_bytes(previous_run)
    if previous_health is not None:(output/'previous_health_summary.json').write_bytes(previous_health)
    if not input_report:
        started=utc();lcov=output/'lcov.info';kassee_lcov=output/'kassee_web_lcov.info';cargo_json=output/'cargo_crap.json';human=output/'crap_report_full.txt'
        host_json=output/'cargo_crap_host.json';firmware_json=output/'cargo_crap_firmware.json';kassee_json=output/'cargo_crap_kassee_web.json'
        host_human=output/'crap_report_host.txt';firmware_human=output/'crap_report_firmware.txt';kassee_human=output/'crap_report_kassee_web.txt'
        coverage_log=output/'coverage_run.txt';crap_log=output/'crap_run.txt'
        crap_log.write_text(f'KasSigner CRAP analysis log\nToolchain: {toolchain}\nScopes: root workspace (LCOV-backed), KasSee Web (LCOV-backed), signer firmware (complexity-only)\n',encoding='utf-8')
        print(f'CRAP analysis is the first QA workload.\nGenerated artifacts will be available before the remaining catalog starts.\nWorking artifact directory: {output}\n')
        cov=['cargo',f'+{toolchain}','llvm-cov','--workspace','--lcov','--ignore-filename-regex',r'unit_tests|online-watcher[\\/]src[\\/]wasm_api[\\/]mod\.rs$','--output-path',str(lcov)]
        kassee_cov=['cargo',f'+{toolchain}','llvm-cov','--manifest-path',str(ROOT/'apps/kassee-web/Cargo.toml'),'--workspace','--lib','--lcov','--ignore-filename-regex','unit_tests','--output-path',str(kassee_lcov)]
        if branch:
            cov.append('--branch');kassee_cov.append('--branch')
        coverage_env={'CARGO_PROFILE_DEV_OPT_LEVEL':dev,'CARGO_PROFILE_TEST_OPT_LEVEL':test}
        print('[CRAP 1/4] Running coverage for each host-testable Rust workspace...')
        print('Coverage profile: dev/test opt-level=0 for source-faithful LLVM function/branch mapping.')
        print('  - Root Cargo workspace')
        run(cov,env=coverage_env,log=coverage_log);nonempty(lcov,'root workspace LCOV coverage data')
        print('  - KasSee Web Rust shell')
        run(kassee_cov,env=coverage_env,log=coverage_log,append=True);nonempty(kassee_lcov,'KasSee Web LCOV coverage data')
        print(f'[CRAP 1/4] PASS: scope-aligned coverage completed (root {lcov.stat().st_size} bytes; KasSee Web {kassee_lcov.stat().st_size} bytes).\n')

        common=['--threshold','30','--missing','pessimistic','--sort','crap']
        host_base=['cargo',f'+{toolchain}','crap','--workspace','--lcov',str(lcov),'--exclude','**/unit_tests/**','--exclude','src/wasm/**',*common]
        kassee_base=['cargo',f'+{toolchain}','crap','--path','apps/kassee-web','--lcov',str(kassee_lcov),'--exclude','**/unit_tests/**',*common]
        firmware_base=['cargo',f'+{toolchain}','crap','--path','apps/signer-firmware','--no-default-excludes',*common]
        print('[CRAP 2/4] Calculating machine-readable CRAP scores by matching scope...')
        print('  - Root Cargo workspace: coverage-backed CRAP')
        run(host_base+['--format','json','--output',str(host_json)],env={'NO_COLOR':'1'},log=crap_log,append=True);nonempty(host_json,'root workspace cargo-crap JSON report')
        print('  - KasSee Web Rust shell: coverage-backed CRAP')
        run(kassee_base+['--format','json','--output',str(kassee_json)],env={'NO_COLOR':'1'},log=crap_log,append=True);nonempty(kassee_json,'KasSee Web cargo-crap JSON report')
        print('  - Signer firmware: complexity-only CRAP (host LCOV is not valid for Xtensa firmware)')
        run(firmware_base+['--format','json','--output',str(firmware_json)],env={'NO_COLOR':'1'},log=crap_log,append=True);nonempty(firmware_json,'signer firmware cargo-crap JSON report')
        merge=[PY,'qa/checks/quality/crap/merge_reports.py','--host-json',str(host_json),'--firmware-json',str(firmware_json),'--kassee-web-json',str(kassee_json),'--output-json',str(cargo_json)]
        run(merge);nonempty(cargo_json,'merged cargo-crap JSON report');print(f'[CRAP 2/4] PASS: machine-readable CRAP scoring completed ({cargo_json.stat().st_size} bytes).\n')

        print('[CRAP 3/4] Rendering the human-readable CRAP report by matching scope...')
        run(host_base+['--format','human','--output',str(host_human)],env={'NO_COLOR':'1'},log=crap_log,append=True);nonempty(host_human,'root workspace human cargo-crap report')
        run(kassee_base+['--format','human','--output',str(kassee_human)],env={'NO_COLOR':'1'},log=crap_log,append=True);nonempty(kassee_human,'KasSee Web human cargo-crap report')
        run(firmware_base+['--format','human','--output',str(firmware_human)],env={'NO_COLOR':'1'},log=crap_log,append=True);nonempty(firmware_human,'signer firmware human cargo-crap report')
        merge += ['--host-human',str(host_human),'--firmware-human',str(firmware_human),'--kassee-web-human',str(kassee_human),'--output-human',str(human)]
        run(merge);nonempty(human,'human-readable cargo-crap report');print(f'[CRAP 3/4] PASS: human-readable report completed ({human.stat().st_size} bytes).\n')

        finished=utc();args=[PY,'qa/checks/quality/crap/coverage_manifest.py','--output',str(output/'run.json'),'--started-at',started,'--finished-at',finished,'--toolchain',toolchain,'--rustc-version',rustc,'--llvm-cov-version',llvm,'--cargo-crap-version',crap,'--dev-opt-level',dev,'--test-opt-level',test,'--root',str(ROOT),'--lcov',str(lcov),'--cargo-crap-json',str(cargo_json)]
        if branch:args.append('--branch-requested')
        run(args);input_report=cargo_json
    if (output/'lcov.info').is_file() and (output/'run.json').is_file():
        print('[Browser recovery] Running KasSee recovery tests with V8 coverage...');run([PY,'qa/checks/web/run_web_recovery_coverage.py','--output-dir',str(output/'browser_recovery')]);nonempty(output/'browser_recovery/summary.json','browser recovery coverage summary');nonempty(output/'browser_recovery/v8-coverage.json','browser recovery V8 coverage')
        print('[Web runtime] Mapping all reachable KasSee JS modules with merged V8 integration coverage...');run([PY,'qa/checks/web/run_web_runtime_coverage.py','--output-dir',str(output/'web_runtime')]);nonempty(output/'web_runtime/summary.json','web runtime coverage summary');nonempty(output/'web_runtime/v8-coverage.json','web runtime V8 coverage')
    print('[CRAP 4/4] Classifying production, tests, external, and tools...')
    cls=[PY,'qa/checks/quality/crap/classify_report.py','--input',str(input_report),'--output-dir',str(output),'--source-label',source_label()]
    if (output/'crap_report_full.txt').is_file():cls += ['--display-report',str(output/'crap_report_full.txt')]
    run(cls)
    check=[PY,'qa/checks/quality/crap/check.py','--report',str(output/'current.json'),'--ratchet-contract',str(ratchet)]
    if ns.strict:check.append('--strict-report')
    if (output/'lcov.info').is_file() and (output/'run.json').is_file():check += ['--lcov',str(output/'lcov.info'),'--run-manifest',str(output/'run.json'),'--browser-recovery-coverage',str(output/'browser_recovery/summary.json'),'--web-runtime-coverage',str(output/'web_runtime/summary.json'),'--health-output',str(output/'health_summary.json')]
    if (output/'previous.json').is_file():check += ['--previous-report',str(output/'previous.json')]
    if (output/'run.json').is_file() and (output/'previous_run.json').is_file():check += ['--previous-run-manifest',str(output/'previous_run.json')]
    if (output/'lcov.info').is_file() and (output/'run.json').is_file() and (output/'previous_health_summary.json').is_file():check += ['--previous-health-summary',str(output/'previous_health_summary.json')]
    run(check)
    print(f'[CRAP 4/4] PASS: reports classified and checked.\n\nFresh CRAP artifacts are ready while the remaining QA tests run:\n  Full report:       {output}/crap_report_full.txt\n  Production report: {output}/crap_report_prod.txt\n  Summary:           {output}/crap_summary.json\n  Health audit:      {output}/health_summary.json\n  LCOV data:         {output}/lcov.info\n\nCommitted quality ratchet:\n  Contract:          {ratchet}\n')
    return 0
if __name__=='__main__':raise SystemExit(main(sys.argv[1:]))
