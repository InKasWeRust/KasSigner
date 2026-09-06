// Focused ZK Crowdfunding session state. Campaign material is copied into the
// active covenant record/owner backup after creation; no window.* globals are used.
export const crowdfundState = Object.seal({
    'role': 'organizer',
    'setup': null,
    'importedCampaign': null,
    'contributions': [],
    'watcherTimer': null,
});
