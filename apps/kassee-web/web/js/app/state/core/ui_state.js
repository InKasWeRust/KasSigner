// Explicit uiState shape. Complex behavior belongs in domain facades; this object holds simple session state.
export const uiState = Object.seal({
    'toastTimer': undefined,
    'autoRefreshTimer': undefined,
    '_refreshExpansionDepth': undefined,
});
