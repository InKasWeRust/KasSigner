#!/usr/bin/env python3
"""Conservative source-complexity CRAP gate for live native iOS shell logic.

Coverage is unavailable without Xcode, so each Swift function is treated as 0%
covered (CRAP = CC^2 + CC). This intentionally keeps the same threshold without
retaining the deleted portable native-wallet package merely to manufacture coverage.
"""
from __future__ import annotations
import json, re, sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[3]
SOURCE=ROOT/'apps/kassee-ios/KasSigner'
OUT=ROOT/'target/qa/ios-crap'
THRESHOLD=30.0
SCOPE=(SOURCE/'Features/Cover/Components', SOURCE/'Infrastructure')
DECL=re.compile(r"\b(?:(?:private|internal|public|static|class|mutating|nonmutating)\s+)*(?:func\s+([A-Za-z_][A-Za-z0-9_]*)|init)\s*(?:<[^>{}]*>)?\s*\(")
DECISIONS=re.compile(r"\b(?:if|guard|for|while|case|catch)\b|&&|\|\||\?\?")

def matching_brace(text, opening):
    depth=0; string=False; escaped=False
    for i in range(opening,len(text)):
        ch=text[i]
        if string:
            if escaped: escaped=False
            elif ch=='\\': escaped=True
            elif ch=='"': string=False
            continue
        if ch=='"': string=True
        elif ch=='{': depth+=1
        elif ch=='}':
            depth-=1
            if depth==0:return i
    return len(text)-1

def functions(path):
    text=path.read_text(encoding='utf-8')
    for m in DECL.finditer(text):
        opening=text.find('{',m.end())
        if opening<0: continue
        closing=matching_brace(text,opening); body=text[opening:closing+1]
        cc=1+len(DECISIONS.findall(body)); name=m.group(1) or 'init'; line=text.count('\n',0,m.start())+1
        yield {'file':path.relative_to(ROOT).as_posix(),'function':name,'line':line,'complexity':cc,'coverage':0.0,'crap':float(cc*cc+cc)}

def main():
    rows=[row for root in SCOPE if root.exists() for path in sorted(root.rglob('*.swift')) for row in functions(path)]
    OUT.mkdir(parents=True,exist_ok=True); failures=[r for r in rows if r['crap']>THRESHOLD]
    (OUT/'report.json').write_text(json.dumps({'threshold':THRESHOLD,'rows':rows,'failures':failures},indent=2)+'\n')
    if not rows: print('ERROR: iOS CRAP scope contained no functions.'); return 1
    for row in failures: print(f"ERROR: iOS source CRAP {row['crap']:.2f}>{THRESHOLD:.0f}: {row['file']}::{row['function']}:{row['line']} (CC {row['complexity']})")
    if failures:return 1
    worst=max(rows,key=lambda r:r['crap']); print(f"PASS: iOS source CRAP ({len(rows)} functions; worst {worst['crap']:.2f}, CC {worst['complexity']}; threshold {THRESHOLD:.0f})."); return 0
if __name__=='__main__': raise SystemExit(main())
