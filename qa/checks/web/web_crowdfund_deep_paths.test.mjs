import assert from 'node:assert/strict';
import {
  setupDeepHarness, cleanupDeepHarness, moduleUrl, element, setValue, tick,
  ADDRESS, PK2, PK3, TXID, covenantResult, assertWatchOnlyStorage,
} from './web_runtime_deep_harness.mjs';

const { state } = await setupDeepHarness();
try {
  const campaignMod = await import(moduleUrl('features/covenants/crowdfund/campaign.js'));
  const model = await import(moduleUrl('features/covenants/crowdfund/model.js'));
  const invites = await import(moduleUrl('features/covenants/crowdfund/invites.js'));
  const persistence = await import(moduleUrl('features/covenants/crowdfund/persistence.js'));
  const sweep = await import(moduleUrl('features/covenants/crowdfund/sweep.js'));
  const events = await import(moduleUrl('app/events/contracts/covenant_specialized/crowdfund.js'));
  const recovery = await import(moduleUrl('features/covenants/recovery/scanner/primary/crowdfund.js'));
  const serializers = await import(moduleUrl('features/covenants/payload_and_swaps/params/advanced.js'));
  const actions = await import(moduleUrl('features/covenants/watchers_and_ui/ui/result_buttons/primary_advanced/crowdfund.js'));
  const stubs = globalThis.__KASSEE_WASM_STUBS__;

  const VK = 'ab'.repeat(48);
  const PK_BYTES = 'cd'.repeat(64);
  const SALT = 'ef'.repeat(8);
  const campaignInvite = Object.freeze({
    v: 2, t: 'crowdfund-campaign', name: 'Runtime Campaign', goal: '200000000', daa: '2000',
    organizer: ADDRESS, vk: VK, id: PK3, date: '2026-08-20T00:00:00.000Z',
  });
  const contribution = Object.freeze({
    address: 'kaspa:runtime-crowdfund', contributor_pubkey_hex: PK2,
    redeem_script_hex: '51', crowdfund_salt_hex: SALT,
  });
  const crowdResult = {
    ...covenantResult('crowdfund'), type: 'crowdfund', address: contribution.address,
    redeem_script_hex: contribution.redeem_script_hex, contributor_pubkey_hex: PK2,
    crowdfund_salt_hex: SALT, crowdfund_role: 'organizer', campaign_name: 'Runtime Campaign',
    organizer_address: ADDRESS, goal_sompi: 200000000n, locktime_daa: 2000n,
    locktime_date_iso: campaignInvite.date, vk_hex: VK, campaign_id: PK3,
    crowdfund_pk_hex: PK_BYTES, crowdfund_contributions_json: JSON.stringify([contribution]),
  };

  stubs.blake2b_hash = () => PK3;
  stubs.crowdfund_campaign_id = () => PK3;
  stubs.zk_crowdfund_setup = () => JSON.stringify({ pk_hex: PK_BYTES, vk_hex: VK, vk_hash_hex: PK3, vk_len: VK.length / 2 });
  stubs.covenant_crowdfund = (...args) => JSON.stringify({
    ...crowdResult, contributor_pubkey_hex: args[0], organizer_address: args[1],
    goal_sompi: String(args[2]), locktime_daa: String(args[3]), vk_hex: args[4],
    vk_hash_hex: PK3, campaign_id: PK3, crowdfund_role: 'contributor',
  });
  stubs.inspect_crowdfund_contributions = () => JSON.stringify({
    contributions: [{ ...contribution, amount_sompi: '200500000' }],
    total_sompi: '200500000', input_count: '1',
  });
  stubs.zk_crowdfund_prove = (_pk, _vk, amounts) => {
    assert.deepEqual(JSON.parse(amounts), ['200500000']);
    return JSON.stringify({ proof_hex: 'aa'.repeat(64), public_input_hex: 'bb'.repeat(32), total_sompi: '200500000', contribution_count: 1, verified: true });
  };
  let swept = false;
  stubs.create_crowdfund_sweep = (...args) => {
    swept = true;
    assert.equal(args[1], ADDRESS);
    assert.equal(args[2], 200000000n);
    return TXID;
  };

  // Pure campaign/contribution validation, duplicate de-duplication, and limits.
  assert.equal(model.normalizeCampaign(campaignInvite).goal, 200000000n);
  assert.throws(() => model.normalizeCampaign({ ...campaignInvite, goal: '0' }), /greater than zero/);
  assert.throws(() => model.normalizeCampaign({ ...campaignInvite, id: '00' }), /campaign ID/);
  assert.equal(model.contributionList([contribution, contribution]).length, 1);
  assert.throws(() => model.contributionList(Array.from({ length: 9 }, (_, i) => ({ ...contribution, address: `kaspa:crowd-${i}` }))), /at most 8/);
  assert.equal(JSON.parse(model.contributionJson([contribution])).length, 1);

  // Role/setup and imported campaign behavior. Campaign identity binds the
  // verifier, goal, refund deadline, and organizer destination before import.
  campaignMod.setCrowdfundRole('organizer');
  campaignMod.populateOrganizerDestination();
  assert.equal(element('cov-crowdfund-organizer-address').value, ADDRESS);
  await campaignMod.runCrowdfundSetup();
  assert.equal(state.crowdfundState.setup.vk_hash_hex, PK3);
  assert.throws(() => { stubs.crowdfund_campaign_id = () => '00'.repeat(32); campaignMod.importCrowdfundCampaign(campaignInvite); }, /does not match/);
  stubs.crowdfund_campaign_id = () => PK3;
  const imported = campaignMod.importCrowdfundCampaign(campaignInvite);
  assert.equal(imported.id, PK3);
  assert.match(element('crowdfund-contributor-summary').textContent, /Runtime Campaign/);
  const contributorBuild = await campaignMod.buildCrowdfund(PK2);
  assert.equal(contributorBuild.extra.crowdfund_role, 'contributor');

  // Organizer form path retains exact amount/DAA values and setup material.
  campaignMod.setCrowdfundRole('organizer');
  state.crowdfundState.setup = Object.freeze({ pk_hex: PK_BYTES, vk_hex: VK, vk_hash_hex: PK3 });
  setValue('cov-crowdfund-name', 'Runtime Campaign');
  setValue('cov-crowdfund-organizer-address', ADDRESS);
  setValue('cov-crowdfund-goal', '2');
  setValue('cov-crowdfund-datetime', new Date(Date.now() + 3600000).toISOString().slice(0, 16));
  const organizerBuild = await campaignMod.buildCrowdfund(PK2);
  assert.equal(organizerBuild.extra.crowdfund_role, 'organizer');
  assert.equal(organizerBuild.extra.goal_sompi, 200000000n);

  // Campaign/contribution QR flows and state persistence.
  state.covenantState.lastCovenantResult = { ...crowdResult };
  state.crowdfundState.contributions = [contribution];
  invites.shareCrowdfundCampaign();
  assert.equal(element('qr-display-title').textContent, 'Crowdfunding Campaign Invite');
  invites.shareCrowdfundContribution();
  assert.equal(element('qr-display-title').textContent, 'Crowdfunding Contribution Invite');
  const parsedCampaign = invites.parseCrowdfundCampaign(new TextEncoder().encode(JSON.stringify(campaignInvite)));
  assert.equal(parsedCampaign.id, PK3);
  const secondContribution = { ...contribution, address: 'kaspa:runtime-crowdfund-2' };
  invites.importCrowdfundContribution(new TextEncoder().encode(JSON.stringify({ v: 2, t: 'crowdfund-contribution', campaign_id: PK3, contribution: secondContribution })));
  assert.equal(state.crowdfundState.contributions.length, 2);
  assert.throws(() => invites.importCrowdfundContribution(new TextEncoder().encode(JSON.stringify({ v: 2, t: 'crowdfund-contribution', campaign_id: '00'.repeat(32), contribution }))), /different/);
  state.covenantState.activeCovenants = [{ ...crowdResult }];
  const persisted = persistence.persistContributions([contribution]);
  assert.equal(persisted.length, 1);
  assert.match(state.covenantState.lastCovenantResult.crowdfund_contributions_json, /runtime-crowdfund/);

  // Organizer result configuration, watcher refresh, proof generation and
  // constrained sweep all run without any wallet raw-hash signature.
  state.covenantState.lastCovenantResult = { ...crowdResult, crowdfund_contributions_json: JSON.stringify([contribution]) };
  state.crowdfundState.contributions = [contribution];
  actions.configureCrowdfundActions({ beneBtn: element('btn-cov-res-bene'), ownerBtn: element('btn-cov-res-owner'), fundBtn: element('btn-cov-res-fund') });
  assert.equal(element('btn-cov-res-owner').textContent, 'Timeout Refund');
  sweep.renderCrowdfundResult();
  assert.match(element('crowdfund-campaign-info').textContent, /Organizer/);
  const refreshed = await sweep.refreshCrowdfundTotals();
  assert.equal(refreshed.total, 200500000n);
  await sweep.sweepCrowdfund();
  assert.equal(swept, true);
  assert.match(element('crowdfund-sweep-status').textContent, /Sweep broadcast/);
  state.covenantState.lastCovenantResult = covenantResult('dms');
  sweep.renderCrowdfundResult();

  // Encrypted-recovery serializer and primary rebuilder round-trip all
  // organizer proving/tracking material and reject trailing bytes.
  stubs.crowdfund_campaign_id = () => PK3;
  const params = serializers.advancedSerializers.crowdfund(crowdResult);
  const recovered = recovery.rebuildCrowdfund('crowdfund', params);
  assert.equal(recovered.campaign_id, PK3);
  assert.equal(recovered.crowdfund_pk_hex, PK_BYTES);
  assert.equal(JSON.parse(recovered.crowdfund_contributions_json).length, 1);
  assert.throws(() => recovery.rebuildCrowdfund('crowdfund', params + '00'), /trailing data/);

  // Fail-closed campaign/setup paths are exercised through the same public
  // organizer/contributor workflow. These are independent validation gates,
  // not coverage-only helper calls.
  assert.throws(() => campaignMod.setCrowdfundRole('spectator'), /Unknown crowdfunding role/);
  campaignMod.setCrowdfundRole('contributor');
  state.crowdfundState.importedCampaign = null;
  campaignMod.renderImportedCampaign();
  assert.match(element('crowdfund-contributor-summary').textContent, /Scan the organizer/);
  assert.equal(await campaignMod.buildCrowdfund(PK2), null);
  assert.match(element('toast').textContent, /Scan a crowdfunding campaign invite/);

  campaignMod.setCrowdfundRole('organizer');
  state.crowdfundState.setup = null;
  assert.equal(await campaignMod.buildCrowdfund(PK2), null);
  assert.match(element('toast').textContent, /Trusted Setup/);
  state.crowdfundState.setup = Object.freeze({ pk_hex: PK_BYTES, vk_hex: VK, vk_hash_hex: PK3 });
  setValue('cov-crowdfund-goal', '1.000000001');
  assert.equal(await campaignMod.buildCrowdfund(PK2), null);
  assert.match(element('toast').textContent, /valid crowdfunding goal/);
  setValue('cov-crowdfund-goal', '0');
  assert.equal(await campaignMod.buildCrowdfund(PK2), null);
  assert.match(element('toast').textContent, /greater than zero/);
  setValue('cov-crowdfund-goal', '1'); setValue('cov-crowdfund-organizer-address', 'bad');
  assert.equal(await campaignMod.buildCrowdfund(PK2), null);
  assert.match(element('toast').textContent, /valid organizer/);
  setValue('cov-crowdfund-organizer-address', ADDRESS); setValue('cov-crowdfund-datetime', '');
  assert.equal(await campaignMod.buildCrowdfund(PK2), null);
  assert.match(element('toast').textContent, /refund deadline/);

  // Trusted setup output itself is treated as hostile until all material is
  // present and the verifier hash is canonical.
  stubs.zk_crowdfund_setup = () => JSON.stringify({ pk_hex:'', vk_hex:VK, vk_hash_hex:PK3 });
  await campaignMod.runCrowdfundSetup();
  assert.match(element('toast').textContent, /setup failed/i);
  stubs.zk_crowdfund_setup = () => { throw new Error('setup backend unavailable'); };
  await campaignMod.runCrowdfundSetup();
  assert.match(element('toast').textContent, /backend unavailable/);
  stubs.zk_crowdfund_setup = () => JSON.stringify({ pk_hex:PK_BYTES, vk_hex:VK, vk_hash_hex:PK3, vk_len:VK.length/2 });

  // Result rendering distinguishes inactive, contributor, organizer, empty and
  // plural contribution-list states and stops/starts its watcher accordingly.
  state.covenantState.lastCovenantResult = null;
  sweep.renderCrowdfundResult();
  assert.equal(element('crowdfund-result-panel').classList.contains('hidden'), true);
  state.covenantState.lastCovenantResult = { ...crowdResult, crowdfund_role:'contributor' };
  sweep.renderCrowdfundResult();
  assert.match(element('crowdfund-campaign-info').textContent, /Contributor/);
  state.crowdfundState.contributions=[]; sweep.renderContributionList();
  assert.match(element('crowdfund-contribution-list').textContent, /No contribution/);
  state.crowdfundState.contributions=[contribution]; sweep.renderContributionList();
  assert.match(element('crowdfund-contribution-list').textContent, /1\/8 contribution address tracked/);
  state.crowdfundState.contributions=[contribution,{...contribution,address:'kaspa:c2'}]; sweep.renderContributionList();
  assert.match(element('crowdfund-contribution-list').textContent, /2\/8 contribution addresses/);

  // Refresh and sweep validate organizer state, tracked contributions, proving
  // material, campaign goal, local proof verification and exact proof total.
  state.covenantState.lastCovenantResult = covenantResult('dms');
  assert.equal(await sweep.refreshCrowdfundTotals(), null);
  assert.match(element('toast').textContent, /organizer crowdfunding record/);
  state.covenantState.lastCovenantResult = { ...crowdResult };
  state.crowdfundState.contributions=[];
  assert.equal(await sweep.refreshCrowdfundTotals(), null);
  assert.match(element('toast').textContent, /No contribution addresses/);
  state.crowdfundState.contributions=[contribution];
  const oldInspect=stubs.inspect_crowdfund_contributions;
  stubs.inspect_crowdfund_contributions=()=>{throw new Error('node inspection failed')};
  assert.equal(await sweep.refreshCrowdfundTotals(), null);
  assert.match(element('toast').textContent, /node inspection failed/);
  stubs.inspect_crowdfund_contributions=oldInspect;

  state.covenantState.lastCovenantResult = { ...crowdResult, crowdfund_pk_hex:'' };
  await sweep.sweepCrowdfund(); assert.match(element('toast').textContent, /proving material/);
  state.covenantState.lastCovenantResult = { ...crowdResult, goal_sompi:'300000000' };
  await sweep.sweepCrowdfund(); assert.match(element('toast').textContent, /goal has not been reached/);
  state.covenantState.lastCovenantResult = { ...crowdResult };
  const oldProve=stubs.zk_crowdfund_prove;
  stubs.zk_crowdfund_prove=()=>JSON.stringify({ proof_hex:'aa', public_input_hex:'bb', total_sompi:'200500000', contribution_count:1, verified:false });
  await sweep.sweepCrowdfund(); assert.match(element('toast').textContent, /proof verification failed/);
  stubs.zk_crowdfund_prove=()=>JSON.stringify({ proof_hex:'aa', public_input_hex:'bb', total_sompi:'200499999', contribution_count:1, verified:true });
  await sweep.sweepCrowdfund(); assert.match(element('toast').textContent, /Proof total does not match/);
  stubs.zk_crowdfund_prove=oldProve;

  // Binding installs all real UI handlers; exercise role/setup/refresh routes.
  events.bindCrowdfundEvents();
  const clickEvent = { preventDefault() {} };
  element('btn-crowdfund-role-contributor').dispatch('click', clickEvent);
  element('btn-crowdfund-role-organizer').dispatch('click', clickEvent);
  element('btn-crowdfund-setup').dispatch('click', clickEvent);
  await tick();
  element('btn-crowdfund-share-campaign').dispatch('click');
  element('btn-crowdfund-share-contribution').dispatch('click');
  element('btn-crowdfund-scan-campaign').dispatch('click', clickEvent);
  state.scannerState.scanCallback(new TextEncoder().encode(JSON.stringify(campaignInvite)));
  state.covenantState.lastCovenantResult = { ...crowdResult };
  state.crowdfundState.contributions = [contribution];
  element('btn-crowdfund-scan-contribution').dispatch('click');
  state.scannerState.scanCallback(new TextEncoder().encode(JSON.stringify({
    v: 2, t: 'crowdfund-contribution', campaign_id: PK3, contribution: secondContribution,
  })));
  element('btn-crowdfund-refresh').dispatch('click');
  element('btn-crowdfund-sweep').dispatch('click');
  element('cov-crowdfund-datetime').dispatch('input');
  await tick();

  assertWatchOnlyStorage();
  console.log('PASS: hardened ZK Crowdfunding campaign, contribution, sweep, QR, persistence, and recovery paths');
} finally {
  await cleanupDeepHarness();
}
