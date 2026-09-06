import assert from 'node:assert/strict';
import {
  setupDeepHarness, cleanupDeepHarness, moduleUrl, element, setFetchHook,
  PK, PK2, PK3, assertWatchOnlyStorage,
} from './web_runtime_deep_harness.mjs';

const { state, response, originalGet } = await setupDeepHarness();
try {
  const socketMod = await import(moduleUrl('features/stealth/index/scanning/live/socket.js'));
  const catchup = await import(moduleUrl('features/stealth/index/scanning/live/catch_up_session.js'));
  const manual = await import(moduleUrl('features/stealth/index/scanning/live_controls/manual.js'));
  const requestQr = await import(moduleUrl('features/stealth/index/scanning/live_controls/request_qr.js'));
  const responseScanner = await import(moduleUrl('features/stealth/index/scanning/live_controls/response_scanner.js'));
  const stubs = globalThis.__KASSEE_WASM_STUBS__;

  // Live websocket: connection, ignored message, KSTL announcement extraction,
  // duplicate suppression, status creation, close, and bounded reconnect.
  const sockets=[];
  class Socket {
    constructor(url){this.url=url;this.readyState=0;sockets.push(this);}
    send(data){this.sent=data;}
    close(){this.readyState=3;this.onclose?.();}
  }
  globalThis.WebSocket=Socket;
  let inserted=null;
  const scanStatus=element('stealth-scan-status');
  scanStatus.parentNode={insertBefore(node){inserted=node;}};
  let missLive=true;
  document.getElementById=id=>{
    if(id==='stealth-live-status' && missLive){missLive=false; return null;}
    return originalGet(id);
  };
  state.stealthState.stealthAnnouncementsR=[];
  socketMod.startLiveSocket('wss://stealth-runtime', new Uint8Array([1,2,3]));
  assert.equal(sockets.length,1); sockets[0].onopen?.(); assert.deepEqual(Array.from(sockets[0].sent),[1,2,3]); assert.equal(inserted?.id,'stealth-live-status');
  sockets[0].onmessage?.({data:new Uint8Array([0,0,0]).buffer});
  const msg=new Uint8Array(90); msg[0]=1; msg[9]=0xff; msg[11]=0x3c;
  const off=20; msg.set([0x4b,0x53,0x54,0x4c],off); msg[off+28]=0x22; msg[off+32]=1; msg.fill(0x7a,off+33,off+65);
  sockets[0].onmessage?.({data:msg.buffer}); assert.equal(state.stealthState.stealthAnnouncementsR.length,1); assert.match(scanStatus.textContent,/candidate R/i);
  sockets[0].onmessage?.({data:msg.buffer}); assert.equal(state.stealthState.stealthAnnouncementsR.length,1,'duplicate live R must not append');
  // Max-R fail closed: a new candidate is ignored once capacity is full.
  state.stealthState.stealthAnnouncementsR=Array.from({length:512},(_,i)=>i.toString(16).padStart(64,'0'));
  msg.fill(0x6b,off+33,off+65); sockets[0].onmessage?.({data:msg.buffer}); assert.equal(state.stealthState.stealthAnnouncementsR.length,512); assert.match(scanStatus.textContent,/list full/i);
  const realTimeout=globalThis.setTimeout; globalThis.setTimeout=fn=>{queueMicrotask(fn); return 1;};
  state.stealthState._stealthScanActive=true; sockets[0].onclose?.(); await new Promise(r=>setImmediate(r)); assert.equal(sockets.length,2,'active scanner reconnects');
  state.stealthState._stealthScanActive=false; sockets[1].onclose?.(); await new Promise(r=>setImmediate(r)); assert.equal(sockets.length,2,'inactive scanner stays closed'); globalThis.setTimeout=realTimeout;
  document.getElementById=originalGet;

  // Historical indexer success, empty result, cap handling, and indexer fallback
  // to the in-browser REST lane scan using exact blue-score integers.
  state.stealthState.stealthIndexerEnabled=true; state.stealthState.stealthAnnouncementsR=[];
  setFetchHook(async url=>String(url).includes('/r?since=0') ? response({json:[PK,PK,'bad',PK2]}) : response({json:{}}));
  await catchup.runHistoricalCatchUp(); assert.deepEqual(state.stealthState.stealthAnnouncementsR,[PK,PK2]); assert.match(scanStatus.textContent,/Found 2 candidate/i);
  state.stealthState.stealthAnnouncementsR=[]; setFetchHook(async()=>response({json:[]})); await catchup.runHistoricalCatchUp(); assert.match(scanStatus.textContent,/No payments/i);
  state.stealthState.stealthAnnouncementsR=Array.from({length:512},(_,i)=>i.toString(16).padStart(64,'0')); setFetchHook(async()=>response({json:[PK3]})); await catchup.runHistoricalCatchUp(); assert.equal(state.stealthState.stealthAnnouncementsR.length,512);
  state.stealthState.stealthAnnouncementsR=[];
  setFetchHook(async (url,opts={})=>{
    const u=String(url);
    if(u.includes('/r?since=0')) return response({json:{not:'array'}});
    if(u.includes('virtual-chain-blue-score')) return response({text:'{"blueScore":1}',json:{blueScore:1}});
    if(u.includes('/transactions/search')) return response({json:[{subnetwork_id:'4b53544c00000000000000000000000000000000',payload:'01'+PK+'00'}]});
    return response({json:{sink:'aa'.repeat(32)}});
  });
  await catchup.runHistoricalCatchUp(); assert.ok(state.stealthState.stealthAnnouncementsR.includes(PK));

  // Manual R UI: build the fallback section, reject while catch-up is active,
  // reject malformed input, accept a canonical value, and deduplicate it.
  let missingManual=true;
  document.getElementById=id=>{
    if(id==='stealth-manual-r-input' && missingManual){missingManual=false; return null;}
    return originalGet(id);
  };
  const panel=element('stealth-scan-panel'); let insertedManual=null; panel.insertBefore=node=>{insertedManual=node;};
  manual.ensureStealthManualRSection(); assert.equal(insertedManual?.id,'stealth-manual-r-section'); document.getElementById=originalGet;
  const add=element('btn-stealth-add-r'); state.stealthState._stealthCatchupRunning=true; state.stealthState.stealthAnnouncementsR=[]; element('stealth-manual-r-input').value=PK; add.onclick(); assert.equal(state.stealthState.stealthAnnouncementsR.length,0,'manual R must be blocked during catch-up');
  state.stealthState._stealthCatchupRunning=false; element('stealth-manual-r-input').value='bad'; add.onclick(); assert.match(element('toast').textContent,/64 hex/i);
  state.stealthState.stealthAnnouncementsR=[]; element('stealth-manual-r-input').value=PK; add.onclick(); assert.deepEqual(state.stealthState.stealthAnnouncementsR,[PK]); element('stealth-manual-r-input').value=PK; add.onclick(); assert.equal(state.stealthState.stealthAnnouncementsR.length,1);
  manual.ensureStealthManualRSection();

  // Device scan-request QR: catch-up/empty guards, batch wrap, single/multi-frame
  // rendering, timer setup, and QR generation failure.
  state.stealthState._stealthCatchupRunning=true; requestQr.showStealthScanQr(); assert.match(scanStatus.textContent,/still running/i);
  state.stealthState._stealthCatchupRunning=false; state.stealthState.stealthAnnouncementsR=[]; requestQr.showStealthScanQr(); assert.match(element('toast').textContent,/No R values/i);
  state.stealthState.stealthAnnouncementsR=[PK,PK2]; state.stealthState._stealthBatchStart=99; stubs.generate_qr_frames=()=>JSON.stringify([{svg:'<svg>one</svg>'}]); requestQr.showStealthScanQr(); assert.equal(state.stealthState._stealthBatchStart,0); assert.match(element('stealth-scan-status').innerHTML,/Scanning R 1–2/);
  stubs.generate_qr_frames=()=>JSON.stringify([{svg:'<svg>1</svg>'},{svg:'<svg>2</svg>'}]); requestQr.showStealthScanQr(); assert.ok(state.stealthState._stealthQrTimer); clearInterval(state.stealthState._stealthQrTimer); state.stealthState._stealthQrTimer=null;
  stubs.generate_qr_frames=()=>{throw new Error('qr runtime fail')}; requestQr.showStealthScanQr(); assert.match(element('toast').textContent,/QR generation failed/i);

  // Scanner response boundary: direct STLR, malformed fragment, out-of-order
  // two-frame assembly, duplicate frame, and invalid frame index. Processing may
  // reject malformed protocol contents, but the scanner must remain controlled.
  responseScanner.scanStealthResultQr(); assert.equal(typeof state.scannerState.scanCallback,'function');
  state.scannerState.scanCallback(new Uint8Array([0,2,0,1]));
  const stlr=new Uint8Array(69); stlr.set([0x53,0x54,0x4c,0x52]);
  const a=stlr.slice(0,35), b=stlr.slice(35); const fa=new Uint8Array(3+a.length); fa.set([0,2,a.length]); fa.set(a,3); const fb=new Uint8Array(3+b.length); fb.set([1,2,b.length]); fb.set(b,3);
  state.scannerState.scanCallback(fb); state.scannerState.scanCallback(fb); state.scannerState.scanCallback(new Uint8Array([2,2,1,9])); state.scannerState.scanCallback(fa);
  await new Promise(r=>setImmediate(r)); assert.equal(state.scannerState._stlrFrames,null);
  responseScanner.scanStealthResultQr();
  const direct=new Uint8Array(69); direct.set([0x53,0x54,0x4c,0x52]); state.scannerState.scanCallback(direct);
  await new Promise(r=>setImmediate(r));

  assertWatchOnlyStorage();
  console.log('PASS: stealth live socket, catch-up, manual, QR, and response scanner paths');
} finally {
  document.getElementById=originalGet;
  await cleanupDeepHarness();
}
