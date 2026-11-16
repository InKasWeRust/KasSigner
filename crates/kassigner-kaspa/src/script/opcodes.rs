// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// The opcode table of rusty-kaspa 01b532e8b553523216471682649693af92f0fd16
// (v2.1.0), crypto/txscript/src/opcodes/mod.rs: names and encoded sizes, no
// semantics, so the device can show what it signs.
//
// Checked in tests/upstream.rs: `opcode_table_matches_upstream` samples the
// names, `opcode_lengths_match_upstream` every length. If the pin moves,
// update the table and let those tests judge. Upstream declares OpFalse and
// OpTrue with an |Alias| prefix; a re-derivation that misses that form misses
// them.

/// Name of every opcode, indexed by its byte. 256 entries, no gaps.
#[rustfmt::skip]
pub const OPCODE_NAMES: [&str; 256] = [
    "OpFalse", "OpData1", "OpData2", "OpData3",
    "OpData4", "OpData5", "OpData6", "OpData7",
    "OpData8", "OpData9", "OpData10", "OpData11",
    "OpData12", "OpData13", "OpData14", "OpData15",
    "OpData16", "OpData17", "OpData18", "OpData19",
    "OpData20", "OpData21", "OpData22", "OpData23",
    "OpData24", "OpData25", "OpData26", "OpData27",
    "OpData28", "OpData29", "OpData30", "OpData31",
    "OpData32", "OpData33", "OpData34", "OpData35",
    "OpData36", "OpData37", "OpData38", "OpData39",
    "OpData40", "OpData41", "OpData42", "OpData43",
    "OpData44", "OpData45", "OpData46", "OpData47",
    "OpData48", "OpData49", "OpData50", "OpData51",
    "OpData52", "OpData53", "OpData54", "OpData55",
    "OpData56", "OpData57", "OpData58", "OpData59",
    "OpData60", "OpData61", "OpData62", "OpData63",
    "OpData64", "OpData65", "OpData66", "OpData67",
    "OpData68", "OpData69", "OpData70", "OpData71",
    "OpData72", "OpData73", "OpData74", "OpData75",
    "OpPushData1", "OpPushData2", "OpPushData4", "Op1Negate",
    "OpReserved", "OpTrue", "Op2", "Op3",
    "Op4", "Op5", "Op6", "Op7",
    "Op8", "Op9", "Op10", "Op11",
    "Op12", "Op13", "Op14", "Op15",
    "Op16", "OpNop", "OpVer", "OpIf",
    "OpNotIf", "OpVerIf", "OpVerNotIf", "OpElse",
    "OpEndIf", "OpVerify", "OpReturn", "OpToAltStack",
    "OpFromAltStack", "Op2Drop", "Op2Dup", "Op3Dup",
    "Op2Over", "Op2Rot", "Op2Swap", "OpIfDup",
    "OpDepth", "OpDrop", "OpDup", "OpNip",
    "OpOver", "OpPick", "OpRoll", "OpRot",
    "OpSwap", "OpTuck", "OpCat", "OpSubstr",
    "OpLeft", "OpRight", "OpSize", "OpInvert",
    "OpAnd", "OpOr", "OpXor", "OpEqual",
    "OpEqualVerify", "OpReserved1", "OpReserved2", "Op1Add",
    "Op1Sub", "Op2Mul", "Op2Div", "OpNegate",
    "OpAbs", "OpNot", "Op0NotEqual", "OpAdd",
    "OpSub", "OpMul", "OpDiv", "OpMod",
    "OpLShift", "OpRShift", "OpBoolAnd", "OpBoolOr",
    "OpNumEqual", "OpNumEqualVerify", "OpNumNotEqual", "OpLessThan",
    "OpGreaterThan", "OpLessThanOrEqual", "OpGreaterThanOrEqual", "OpMin",
    "OpMax", "OpWithin", "OpZkPrecompile", "OpBlake2bWithKey",
    "OpSHA256", "OpCheckMultiSigECDSA", "OpBlake2b", "OpCheckSigECDSA",
    "OpCheckSig", "OpCheckSigVerify", "OpCheckMultiSig", "OpCheckMultiSigVerify",
    "OpCheckLockTimeVerify", "OpCheckSequenceVerify", "OpTxVersion", "OpTxInputCount",
    "OpTxOutputCount", "OpTxLockTime", "OpTxSubnetId", "OpTxGas",
    "OpTxPayloadSubstr", "OpTxInputIndex", "OpOutpointTxId", "OpOutpointIndex",
    "OpTxInputScriptSigSubstr", "OpTxInputSeq", "OpTxInputAmount", "OpTxInputSpk",
    "OpTxInputDaaScore", "OpTxInputIsCoinbase", "OpTxOutputAmount", "OpTxOutputSpk",
    "OpTxPayloadLen", "OpTxInputSpkLen", "OpTxInputSpkSubstr", "OpTxOutputSpkLen",
    "OpTxOutputSpkSubstr", "OpTxInputScriptSigLen", "OpUnknown202", "OpAuthOutputCount",
    "OpAuthOutputIdx", "OpNum2Bin", "OpBin2Num", "OpInputCovenantId",
    "OpCovInputCount", "OpCovInputIdx", "OpCovOutputCount", "OpCovOutputIdx",
    "OpChainblockSeqCommit", "OpOutputCovenantId", "OpOutputAuthorizingInput", "OpCheckSigFromStack",
    "OpCheckSigFromStackECDSA", "OpBlake3", "OpBlake3WithKey", "OpUnknown219",
    "OpUnknown220", "OpUnknown221", "OpUnknown222", "OpUnknown223",
    "OpUnknown224", "OpUnknown225", "OpUnknown226", "OpUnknown227",
    "OpUnknown228", "OpUnknown229", "OpUnknown230", "OpUnknown231",
    "OpUnknown232", "OpUnknown233", "OpUnknown234", "OpUnknown235",
    "OpUnknown236", "OpUnknown237", "OpUnknown238", "OpUnknown239",
    "OpUnknown240", "OpUnknown241", "OpUnknown242", "OpUnknown243",
    "OpUnknown244", "OpUnknown245", "OpUnknown246", "OpUnknown247",
    "OpUnknown248", "OpUnknown249", "OpSmallInteger", "OpPubKeys",
    "OpUnknown252", "OpPubKeyHash", "OpPubKey", "OpInvalidOpCode",
];

/// Encoded size of every opcode, indexed by its byte.
///
/// Positive: total bytes, the opcode included. Negative: a variable-length
/// push whose length field (1, 2 or 4 bytes, little-endian) follows.
#[rustfmt::skip]
pub const OPCODE_LENGTHS: [i8; 256] = [
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
    17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
    33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48,
    49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64,
    65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, -1, -2, -4, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
];
