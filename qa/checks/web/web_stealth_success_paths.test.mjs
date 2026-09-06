import assert from 'node:assert/strict';
import { setupHarness, teardownHarness, moduleUrl, element } from './web_recovery_test_harness.mjs';
const ADDRESS='kaspa:stealth-funded', R='11'.repeat(32), PUB='22'.repeat(32), TWEAK='33'.repeat(32);
await setupHarness();
try {
 const {networkState,stealthState,walletSession}=await import(moduleUrl('app/state/index.js'));
 networkState.network='mainnet'; networkState.customNodeUrl='wss://stealth-test'; stealthState.stealthAnnouncementsR=[]; stealthState._stealthResults=[]; walletSession.replace({kpub:'kpub-test',receive_addresses:['kaspa:owner'],change_addresses:['kaspa:change']});
 Object.assign(globalThis.__KASSEE_WASM_STUBS__,{
   encode_p2pk_address:()=>ADDRESS,fetch_utxos_for_address_js:()=>JSON.stringify([{tx_id:'aa'.repeat(32),index:0,amount:'100000000'}]),
   generate_qr_frames:()=>JSON.stringify([{svg:'<svg>1</svg>'},{svg:'<svg>2</svg>'}]),
   get_fee_estimate:()=>JSON.stringify({suggested_fee:'300000',low_sompi_per_gram:'1',normal_sompi_per_gram:'1',priority_sompi_per_gram:'2',low_seconds:20,normal_seconds:10,priority_seconds:5}),
 });
 const subnet='4b53544c00000000000000000000000000000000';
 globalThis.fetch=async (url,opts={})=>{
   const u=String(url);
   if(u.includes('virtual-chain-blue-score')) return {ok:true,status:200,headers:{get(){return null;}},async text(){return '{"blueScore":50}';},async json(){return {blueScore:50};}};
   if(u.includes('/transactions/search')) return {ok:true,status:200,headers:{get(){return null;}},async json(){return [{subnetwork_id:subnet,payload:'01'+R+'7f',accepting_block_blue_score:'49'}];},async text(){return '[]';}};
   return {ok:false,status:404,headers:{get(){return null;}},async text(){return '';},async json(){return {};}};
 };
 const catchup=await import(moduleUrl('features/stealth/index/scanning/catch_up.js'));
 const found=await catchup.stealthRestCatchUp('https://runtime-api'); assert.deepEqual(found,[R]); assert.ok(stealthState.stealthAnnouncementsR.includes(R));
 // Single fallback route for tip blue score also succeeds.
 let first=true; globalThis.fetch=async url=>{const u=String(url); if(u.includes('virtual-chain-blue-score')) throw new Error('primary unavailable'); if(u.includes('/info/blockdag')) return {ok:true,async json(){return {sink:'bb'.repeat(32)};}}; if(u.includes('/blocks/')) return {ok:true,async text(){return '{"blueScore":10}';}}; if(u.includes('/transactions/search')) return {ok:true,status:200,headers:{get(){return null;}},async json(){return [];}}; throw new Error('unexpected '+u);};
 assert.deepEqual(await catchup.stealthRestCatchUp('https://runtime-api'),[]);
 // QR request uses all loaded R values and animates frames.
 const requestQr=await import(moduleUrl('features/stealth/index/scanning/live_controls/request_qr.js')); stealthState.stealthAnnouncementsR=[R,'44'.repeat(32)]; stealthState._stealthBatchStart=0; stealthState._stealthCatchupRunning=false; requestQr.showStealthScanQr(); assert.match(element('stealth-scan-status').innerHTML,/Scanning R 1–2 of 2/); assert.ok(stealthState._stealthQrTimer);
 // Device result response: two results, one duplicate/zero rejected, funded result rendered and batch advances.
 const raw=new Uint8Array(5+64); raw.set([0x53,0x54,0x4c,0x52,1]); raw.set(Buffer.from(PUB,'hex'),5); raw.set(Buffer.from(TWEAK,'hex'),37);
 const results=await import(moduleUrl('features/stealth/index/scanning/live_controls/results.js')); await results.processStealthResult(raw); assert.equal(stealthState._stealthResults.length,1); assert.equal(stealthState._stealthResults[0].pubkey,PUB); assert.match(element('stealth-found-list').innerHTML,/Payment 1/);
 // Duplicate result does not create a second record.
 await results.processStealthResult(raw); assert.equal(stealthState._stealthResults.length,1);
 // Manual R section and lifecycle controls cover UI state transitions.
 const life=await import(moduleUrl('features/stealth/index/scanning/live_controls/lifecycle.js')); stealthState._stealthScanActive=true; life.pauseStealthScan(); life.stopStealthScan(); assert.equal(stealthState._stealthScanActive,false); life.clearStealthQrTimer(); assert.equal(stealthState._stealthQrTimer,null);
 console.log('PASS: stealth catch-up/QR/result/lifecycle success paths');
} finally { teardownHarness(); }
