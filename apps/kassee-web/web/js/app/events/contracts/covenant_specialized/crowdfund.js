import { showScreen } from '../../../navigation.js';
import { toast } from '../../../../core/ui/toast.js';
import { byId } from '../../../../core/dom.js';
import {
    importCrowdfundCampaign,
    populateOrganizerDestination,
    runCrowdfundSetup,
    setCrowdfundRole,
} from '../../../../features/covenants/crowdfund/campaign.js';
import {
    importCrowdfundContribution,
    parseCrowdfundCampaign,
    shareCrowdfundCampaign,
    shareCrowdfundContribution,
} from '../../../../features/covenants/crowdfund/invites.js';
import { refreshCrowdfundTotals, sweepCrowdfund } from '../../../../features/covenants/crowdfund/sweep.js';
import { startScanner, stopScanner } from '../../../../features/stealth/index/camera.js';

export function bindCrowdfundEvents() {
    byId('btn-crowdfund-role-organizer')?.addEventListener('click', event => {
        event.preventDefault(); setCrowdfundRole('organizer');
    });
    byId('btn-crowdfund-role-contributor')?.addEventListener('click', event => {
        event.preventDefault(); setCrowdfundRole('contributor');
    });
    byId('btn-crowdfund-setup')?.addEventListener('click', event => {
        event.preventDefault(); void runCrowdfundSetup();
    });
    byId('btn-crowdfund-scan-campaign')?.addEventListener('click', event => {
        event.preventDefault();
        startScanner('Scan Crowdfunding Campaign Invite', raw => {
            try {
                const campaign = parseCrowdfundCampaign(raw);
                stopScanner();
                importCrowdfundCampaign(campaign);
                showScreen('covenant');
                toast('Crowdfunding campaign loaded', 'ok', 2500);
            } catch (error) {
                toast('Invalid crowdfunding campaign: ' + error.message, 'error', 5000);
            }
        });
    });
    byId('btn-crowdfund-share-campaign')?.addEventListener('click', shareCrowdfundCampaign);
    byId('btn-crowdfund-share-contribution')?.addEventListener('click', shareCrowdfundContribution);
    byId('btn-crowdfund-scan-contribution')?.addEventListener('click', () => {
        startScanner('Scan Crowdfunding Contribution Invite', raw => {
            try {
                stopScanner();
                importCrowdfundContribution(raw);
                showScreen('covenant');
            } catch (error) {
                toast('Invalid crowdfunding contribution: ' + error.message, 'error', 5000);
            }
        });
    });
    byId('btn-crowdfund-refresh')?.addEventListener('click', () => { void refreshCrowdfundTotals(); });
    byId('btn-crowdfund-sweep')?.addEventListener('click', () => { void sweepCrowdfund(); });
    byId('cov-crowdfund-datetime')?.addEventListener('input', () => {
        const locktime = byId('cov-crowdfund-locktime');
        if (locktime) locktime.value = '';
    });
    populateOrganizerDestination();
}
