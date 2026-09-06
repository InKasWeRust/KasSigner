import { oracleState, walletSession } from '../../../../../app/state/index.js';
import { kasToSompi } from '../../../../../core/amounts.js';
import { openPsktReview } from '../../../../transactions/pskt_multisig/review.js';
import { oracleMbOracleAddress, oracleMbPublish } from '../../protocol.js';
import { spliceOracleServiceFee } from './fee.js';

export async function openOracleSkeleton({ identity, protocol, journalHex, ambientStop, show }) {
    if (!walletSession.hasWallet()) {
        show('Unlock your wallet first.', '#ffd600');
        return false;
    }
    if (!oracleState._oracleMbState) {
        show('Could not read the current oracle to spend.', '#ff4d4d');
        return false;
    }
    const wallet = walletSession.current();
    const changeAddress = wallet.change_addresses[wallet.next_change_index || 0];
    const current = oracleMbOracleAddress(oracleState._oracleMbState.price, oracleState._oracleMbState.t);
    const totalKas = oracleState._oracleMbFeeTotalKas || '1';
    const pskb = await oracleMbPublish({
        walletJson: walletSession.json(),
        oracleAddress: current.address,
        oracleRedeemHex: current.redeem_script_hex,
        covenantIdG: identity.oracleCovIdG,
        seal: '',
        claim: '',
        controlIndex: '',
        controlDigests: '',
        journal: journalHex,
        fee: kasToSompi(totalKas),
        changeAddress,
    });
    let withFee;
    try {
        withFee = spliceOracleServiceFee(pskb, protocol);
    } catch (error) {
        show(`Could not add the service fee: ${error?.message || error}`, '#ff4d4d');
        return false;
    }
    ambientStop();
    openPsktReview(withFee);
    oracleState._oracleMbRollActive = true;
    return true;
}
