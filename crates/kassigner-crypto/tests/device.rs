// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

//! Conformance against the v1.0.7 firmware, from its recorded outputs.
//!
//! ECIES has no published vectors: its components are standard, but the
//! ordering, domain tag and wire layout are this project's, so the firmware
//! is the only external check. Unlike the KSPT corpus, which lists its
//! deliberate divergences, nothing here changed on purpose: a payload
//! encrypted on one side must open on the other, so every test asserts
//! exact bytes.

use kassigner_crypto::ecies::{decrypt, encrypt, encrypted_size};
use kassigner_crypto::sign::public_key;
use kassigner_protocol::container::SALT_SIZE;
use kassigner_protocol::ecies::NONCE_SIZE;

#[path = "../../../testkit/hex.rs"]
pub mod hex;
use hex::{hex, unhex, unhex_array};

/// (name, recipient key, its x-only form, ephemeral, nonce, plaintext, wire)
///
/// Recorded from `core/src/wallet/ecies.rs` at 1.0.7.
#[rustfmt::skip]
const CASES: &[(&str, &str, &str, &str, &str, &str, &str)] = &[
    ("empty", "0101010101010101010101010101010101010101010101010101010101010101", "1b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f", "1111111111111111111111111111111111111111111111111111111111111111", "212121212121212121212121", "", "034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa21212121212121212121212111f4d9ad598c99f16dbe0a925fa942aa"),
    ("one_byte", "0202020202020202020202020202020202020202020202020202020202020202", "4d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d0766", "1212121212121212121212121212121212121212121212121212121212121212", "222222222222222222222222", "03", "036360e856310ce5d294e8be33fc807077dc56ac80d95d9cd4ddbd21325eff73f7222222222222222222222222a217f96a334540c4553c48b07ca84f19f4"),
    ("block", "0303030303030303030303030303030303030303030303030303030303030303", "531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe337", "1313131313131313131313131313131313131313131313131313131313131313", "232323232323232323232323", "030a11181f262d343b424950575e656c", "031d16453b3ab3132acb0a5bc16cc49690d819a585267a15cd5a064e2a0ad40599232323232323232323232323ed0d96dd7cf40abd2589d9afd41d4f07a0cf904423d77fefde2e0c84c4e73e3c"),
    ("block_plus", "0404040404040404040404040404040404040404040404040404040404040404", "462779ad4aad39514614751a71085f2f10e1c7a593e4e030efb5b8721ce55b0b", "1414141414141414141414141414141414141414141414141414141414141414", "242424242424242424242424", "030a11181f262d343b424950575e656c73", "03ff8adab52623bcb2717fc71d7edc6f55e98396e6c234dff01f307a12b2af1c992424242424242424242424249b99803e8bed7d99b6092573556d537e252bcc993e3c0aece873752e8979fab50d"),
    ("covenant_typ", "0505050505050505050505050505050505050505050505050505050505050505", "62c0a046dacce86ddd0343c6d3c7c79c2208ba0d9c9cf24a6d046d21d21f90f7", "1515151515151515151515151515151515151515151515151515151515151515", "252525252525252525252525", "030a11181f262d343b424950575e656c737a81888f969da4abb2b9c0c7ced5dce3ea", "03d793631af7aa0e709439dd47fc001acd0b0727670b6670ea528ac83cb0127f4a25252525252525252525252503c05f9e95b289b4462b776f079b06cc201fb6068bf32ccdc1d80a7dc1758047f1d89e6b727108244813cbc4f59c5becc838"),
    ("long", "0606060606060606060606060606060606060606060606060606060606060606", "f006a18d5653c4edf5391ff23a61f03ff83d237e880ee61187fa9f379a028e0a", "1616161616161616161616161616161616161616161616161616161616161616", "262626262626262626262626", "030a11181f262d343b424950575e656c737a81888f969da4abb2b9c0c7ced5dce3eaf1f8ff060d141b222930373e454c535a61686f767d848b9299a0a7aeb5bcc3cad1d8dfe6edf4fb020910171e252c333a41484f565d646b727980878e959ca3aab1b8bfc6cdd4dbe2e9f0f7fe050c131a21282f363d444b525960676e757c838a91989fa6adb4bbc2c9d0d7dee5ecf3fa01080f161d242b323940474e555c636a71787f868d949ba2a9b0b7bec5ccd3dae1e8eff6fd040b121920272e353c434a51585f666d747b828990979ea5acb3bac1c8cfd6dde4ebf2f900070e151c232a31383f464d545b626970777e858c939aa1a8afb6bdc4cbd2d9e0e7eef5fc030a11181f262d343b424950575e656c737a81888f969da4abb2b9c0c7ced5dce3eaf1f8ff060d141b222930373e454c535a61686f767d848b9299a0a7aeb5bcc3cad1d8dfe6edf4fb020910171e252c333a41484f565d646b727980878e959ca3aab1b8bfc6cdd4dbe2e9f0f7fe050c131a21282f363d444b525960676e757c838a91989fa6adb4bbc2c9d0d7dee5ecf3fa01080f161d242b323940474e555c636a71787f868d949ba2a9b0b7bec5ccd3dae1e8eff6fd040b121920272e353c434a51585f666d747b828990979ea5acb3bac1c8cfd6dde4ebf2f900070e151c232a31383f464d545b626970777e858c939aa1a8afb6bdc4cbd2d9e0e7eef5fc", "02a8397a935f0dfceba6ba9618f6451ef4d80637abf4e6af2669fbc9de6a8fd2ac2626262626262626262626260c210e1a5b76cdec0fa0c5b811984ab9e87ec7d3ac8187e6d766d27e88210e6ff4251e1cda01b4aa6de36f70f2bd6dc83c6ec1a6f9d48c4cf2199bd0fd87a8a3b487cbe7ac13edb3e228c59fa558e4539926c414f533e8aca3804596f8c14689f00732fd086821bfcea5d16a5fe9baa322d1f9ff07fc72dd1f1f37250624da818446805b74f891c22f6763b53f2e22ada3c08a5d065e0c10dccd47a72c07aca38f9542f029a13fb1b03888b24e107cec7792b0041d6118afcc6c437f2cbc9978f0fc4238c812f900758c8dbed77bbcb2dff7b3f4eac61d741cff8bee187687c59b459fc2381d4d6b770bd84b96cfb7114e15e47c67b575c9b5967c4a16d92c7e27196f80bc60c0d7592724c53498ce05767a11ee385312235036c157250bc1f65dc6d4eb6e013e68c76c5f95a9ef29a797285ae527faced324f2764b5074b904078386b8d75c089a7a7540653df26a18831e6a3b9aab02961b96718f0e0134cdaa3fb458cac856c3c4ae626af80799c7405a2f4c2cb4dbe8b807756515f07bfaf5beff0f9ef9f035d6b06a9373e317d94fa02a1e19f9cac7ec9eee35ae66a122ee725e46e5f325526faffce263cf391706f8b46031a97df28ae25f7df0ae21a6159f1be08b37dc56cf522a3b940aea4f361825c6925062ad00218c4328a9c32e07c791c3bee8d5d23393bd17a1998d0e6bc64eed7a7acc7e69d35150f8f652c6af5fbb39638875d9bc585b7d69e6052f"),
    ("odd_y_a", "0707070707070707070707070707070707070707070707070707070707070707", "989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6f", "1717171717171717171717171717171717171717171717171717171717171717", "272727272727272727272727", "030a11181f262d343b424950575e656c737a81888f969da4abb2b9c0c7ced5dc", "0257eb3638f51f4dc5c8d5a7324b47df99e816cfcc5b5eb1245bc8c98029f9e67427272727272727272727272769c610073203fb58d103b320a3b417ccad001fc8ae2c68b151c7403f488f5c6a385b95dd8f9faa565bef5d00e1988e7e"),
    ("odd_y_b", "0808080808080808080808080808080808080808080808080808080808080808", "f991f944d1e1954a7fc8b9bf62e0d78f015f4c07762d505e20e6c45260a3661b", "1818181818181818181818181818181818181818181818181818181818181818", "282828282828282828282828", "030a11181f262d343b424950575e656c737a81888f969da4abb2b9c0c7ced5dc", "0329ce758bb2d21def214cea069addbd16896ec77924bf0ec9219e00dcf077605e282828282828282828282828fc4152020937c8d31db129edd4a978164ba85c683f36182a263c502afdda72ecb660540b3f611ce54b5ae38da1cdfab2"),
    ("odd_y_c", "0909090909090909090909090909090909090909090909090909090909090909", "56b328b30c8bf5839e24058747879408bdb36241dc9c2e7c619faa12b2920967", "1919191919191919191919191919191919191919191919191919191919191919", "292929292929292929292929", "030a11181f262d343b424950575e656c737a81888f969da4abb2b9c0c7ced5dc", "02e4d24944ed947bc34ed14ea4b2e063aa27ebd8da658577a263f55a631c7f656a292929292929292929292929236b912d26d26940c4d091a7245ec109165c96dbb0d2f2c50d5b509306b9242033d1deb905b0daac36a7323f3753602d"),
];

/// (name, password, salt, derived key), from `core/src/wallet/storage.rs`.
#[rustfmt::skip]
const PBKDF2: &[(&str, &str, &str, &str)] = &[
    ("empty_password", "", "11111111111111111111111111111111", "411c9745f362f259fb969c7ba99a07bef127b7df773513689e085ef8588c31f1"),
    ("short", "7077", "11111111111111111111111111111111", "27170f53a636b99eda7f4183f89ffa6a0bea544ca9f86e963ced99d09b076502"),
    ("phrase", "636f727265637420686f727365206261747465727920737461706c65", "11111111111111111111111111111111", "139d126dc95423fca7d3a45a4452fcbc0e86788f512e25dd7a22307b58e45786"),
    ("other_salt", "636f727265637420686f727365206261747465727920737461706c65", "22222222222222222222222222222222", "491755cf958afb3deafa232d2808bc765d14b9f4afca980bf518cd19233a2d36"),
];

/// Raw PBKDF2 over a salt, as `core::wallet::storage::pbkdf2_sha256`.
/// `container::derive_key` appends the purpose byte, the container's rule,
/// so the recorded values are compared with the bare function.
fn derive_key_raw(password: &[u8], salt: &[u8]) -> [u8; 32] {
    use hmac::Hmac;
    use sha2::Sha256;
    let mut key = [0u8; 32];
    pbkdf2::pbkdf2::<Hmac<Sha256>>(password, salt, 100_000, &mut key).expect("length");
    key
}

/// Every recorded ciphertext is reproduced byte for byte: with the ephemeral
/// scalar and nonce fixed, a wrong domain tag, hash input order or point
/// encoding shows here, not as something that only decrypts on this side.
#[test]
fn every_ciphertext_matches_the_firmware() {
    for (name, _sk, pk, eph, nonce, plaintext, wire) in CASES {
        let pk = unhex_array::<32>(pk);
        let eph = unhex_array::<32>(eph);
        let nonce: [u8; NONCE_SIZE] = unhex_array(nonce);
        let plaintext = unhex(plaintext);

        let mut out = vec![0u8; encrypted_size(plaintext.len())];
        let n = encrypt(&pk, &plaintext, &eph, &nonce, &mut out)
            .unwrap_or_else(|e| panic!("{name}: {e:?}"));

        assert_eq!(hex(&out[..n]), *wire, "{name}: the recipe diverged");
    }
}

/// Every recorded ciphertext opens with this crate: a covenant payload a
/// companion encrypted on the old code must open on a unit running the new.
#[test]
fn every_recorded_ciphertext_decrypts() {
    for (name, sk, _pk, _eph, _nonce, plaintext, wire) in CASES {
        let sk = unhex_array::<32>(sk);
        let plaintext = unhex(plaintext);
        let wire = unhex(wire);

        let mut out = vec![0u8; plaintext.len()];
        let n = decrypt(&sk, &wire, &mut out).unwrap_or_else(|e| panic!("{name}: {e:?}"));
        assert_eq!(n, plaintext.len(), "{name}: length");
        assert_eq!(out, plaintext, "{name}: plaintext");
    }
}

/// The x-only key this crate derives is the firmware's: the join between
/// `sign::public_key` and everything that names a recipient.
#[test]
fn the_recipient_keys_agree() {
    for (name, sk, pk, _eph, _nonce, _pt, _wire) in CASES {
        let derived =
            public_key(&unhex_array::<32>(sk)).unwrap_or_else(|e| panic!("{name}: {e:?}"));
        assert_eq!(hex(&derived), *pk, "{name}");
    }
}

/// The overhead is 61 bytes, on every case.
#[test]
fn the_overhead_is_what_the_format_says() {
    for (name, _sk, _pk, _eph, _nonce, plaintext, wire) in CASES {
        let pt = unhex(plaintext).len();
        let w = unhex(wire).len();
        assert_eq!(w - pt, 61, "{name}: 33 + 12 + 16");
        assert_eq!(w, encrypted_size(pt), "{name}");
    }
}

/// Both ephemeral parities appear: the compressed key's first byte is 0x02
/// or 0x03 by its y, so both encoding branches run.
#[test]
fn the_corpus_covers_both_ephemeral_parities() {
    let mut even = false;
    let mut odd = false;
    for (_name, _sk, _pk, _eph, _nonce, _pt, wire) in CASES {
        match unhex(wire)[0] {
            0x02 => even = true,
            0x03 => odd = true,
            other => panic!("not a compressed prefix: {other:#04x}"),
        }
    }
    assert!(even && odd, "the corpus must cover both");
}

/// PBKDF2 at 100,000 rounds, what `kdf_id = 1` means, matches the
/// firmware's.
#[test]
fn pbkdf2_matches_the_firmware() {
    for (name, password, salt, key) in PBKDF2 {
        let password = unhex(password);
        let salt: [u8; SALT_SIZE] = unhex_array(salt);
        // Recorded over the salt alone, as the firmware's `pbkdf2_sha256`
        // does, so compared with the bare function, no purpose byte.
        let derived = derive_key_raw(&password, &salt);
        assert_eq!(hex(&derived), *key, "{name}");
    }
}

// ── Real containers, written by a device ─────────────────────────────────────

/// A `KAS\x06` container written by v1.0.7, password "abc": `seal` and
/// `open` agreeing with each other would hide a fault they share.
const REAL_V1: &str = concat!(
    "4b4153060104013a0f3e480c0ce5740bc3776e48838ff996b3ad6a1066b43e0418fa82224e72df85f2d7dba5263529e7",
    "1db2f52bb6fadce98e23f7e26bc7316b086831c9606eabe2b587be2d9f091ecaeacdd2d798e3c0712128b534de68354d",
    "dba598e2612ea78182be98686d16189a2ffaefc9e8e226f3c549830db32a159b84af62ab800ce604f183cc6b1e0ab5ba",
    "7ef5efe30e1579bb445a3ca1d5007f8098c9e343589a4927a4f5420751a5c57ef38968ddaf5eb2b8e52a48c584dba0cc",
    "cea5202d43498e2aef9539ef16c620ee6c510c88bffd6fe6b5838788695ff13ea673c78a6c4f42b8d65b972dd3a91698",
    "4aac3b7478539e409319c10c22f0c7539dc68a8ca530170ba18d9b2f2346d35af19bbfd534e9bcdefcee46d13e14387e",
    "2fcc7068ae255b4a4cab3a407fc10382109310292ae0c215c30df89c94a8945a9256ac9bce01f6e64d18fc3ccc2af272",
    "85c6998a9e7b735e03caa5d20a66db241076d73e28c18c17a673f38c8967b11e6f058d1db80cc81fe53623532c201d32",
    "04eae972189c0b3676cba7576c665f95baa4fa60c20b66f894e211ea40ba7b8ebf2adbb925a97c1d2f096151fd736ba7",
    "ac606d69c3e7b1a3405209c517d330d7cae176749ac34f67c70dfc278c4d17a50405095a25cc456b4fb68e5f5786f8e5",
    "5b308505389a6e849c894bd0a7b1804f13ab80a1c53300fe5aad3a1c51edc985699c3f35a4009e5ff8fabdf9ed7342f0",
    "527a2672a457931fd6cebba6a7d3705ebe3ac183c2d7c39bde4f03a2b74509a77f2b693c291f4589b5ca4bbb3aa6833b",
    "d6275caab70ad8496b013633bb3e94cf8a0b63dd04b4526ffabceff3e475916a256fe83ea4b644f938284c5451e2c1bb",
    "0857cffb556bddb7e3f82ed0b4b1c37f39e6333ff1700b481a90aaca71e16499199640a1f19cf87d40f5d61e5ef02ed5",
    "1c4459f590649bb7aa84096d5166d0fdf31bfe8f9f8389a10ceade8002444e7f7c75619b5d1d05726b8ca93c035e472d",
    "6579da5da3de2b5a1ba5cd2aba6fd04fac1c2c6008bd071f81d3e9bd37392aba0477da9db610d628f8976c094764287c",
    "bb3e85773cffe191cac6fd96260eafa97a802a07518cae52dcd00cb8635c343fe42d6e3fb6a9d4bd3dc5495245d927e8",
    "c483d4d3fc1162d377e98348072561f7165cf0f1404bbc760512606e0cae46036ca441ad3a3d155813e86cc28b7dd4a6",
    "564fb78a0b40b45d96d3794e97bab6094dc6f73ea24cb28aa4668ef188571dee72a0860322c8c70f32263d68141ea9c6",
    "87b1f89482aa805daf887210810fda3c38f661fe563129afdb8434af1b789e0196c262833d966abf0597e909d8e445b4",
    "4f116b0e58ae7ad455ac88c46ff8b7c9d3499590a83a503a7ea0db4506ad3e28d2fdc0a0171bedf0338fbfb37eedf6c5",
    "c89bfcb923088eb8989c67e2060f3c7e774de9ca4315bfb049e1b7c624378ca7748ae3be0c6fc9d20d731de11eb97528",
    "3c39aa58a659107a9206b74d73801371fdcdae467ac6aaad9b3a3f02616f518f266d852468f6392076ef23dbcf64851c",
    "9c0e11e68fb5fccb2126da79f7ba4a9ed76cdc8dc22ffd955e7b018b4054c24fdf3e836d3b8057a003fdf08bba13565f",
    "cf72268ec54b415614e511e32b73de37f123ed7e114332bbc8bcaf6d466ff7cd1da4254de51a69d9e510c8c0d4b40764",
    "b8518aa119239d6df06ec34006160f452c5aff4e3cb6ce1af93be36b236d70c203e2a8d92d70df2e565bd14155e9be92",
    "c236c40bdbc561131492dac2fb46df76c0bc7029d84957a52e2aba7a412fa34b4d6a0d1f11729df9380472978b41fbc4",
    "cac627e3ca5364a591cd3a1396b102093a27f060ca4ec21067f17cee7ff86920de47eee72b4ffe8e5812afffdfff8d86",
    "ceadec3b781edf90ca8e1d8fb4970988c0a4c5f78a6b7fa8b1b80e59878872bc75eca03d8a82866a79d55efc8d0497f9",
    "f4faea412967d4934080539eeb2ac79189e996533455502ca39a21d757e7469d7b7ccc0131304bb74482331646fde57e",
    "28504f503258d29a207c2817647a38a32e129e667a9473bf87cd408c4559dbb36fe17601b38be81ec6d357ffa40bee99",
    "87b9ddbb37f5ee177f63998e181d166249875453ae1be258ad91035313c8994c611f6b5cf90fd6b489424a03ea9c9786",
    "cb09ab40775943e9a5ecad1e9dbeda7fd37fb2909c0bb2c667bac1cbdab84bcab420a5b4a54f424cdeda82ed9b7f53a5",
    "bf225876c9577ba00ac03300f42c1e95168484441552c05d60b9273391c522189344f3d14d8cac1a4795d6db34c53b9b",
    "4cdd359c7435f27d96f8623336fd257cff7c51fc3791dde39629f9c1a66f49e978dd7cba4b9b054c49e2446d684163d1",
    "852275dc32e8907f7be780a0d5defe4358e559b5fb8e25896c28a68445123f2b8933639211d97bc16d5c5a415f38f2e7",
    "3e42f8cfbaf2e9649e222c475017dfc4ef7386d385fc13e9ce31997ab42f73764f7d6797240ee66b2ed77197eb2020c6",
    "71512a340cc4c296aadf0f302ac88634035e43aece476d42659344ca3d3ed5ffba604cabbfbc2ad8bfdfc7bf70ad0a46",
    "d11978a9107a08d1651861ae70c190f89bb6ad5e67fec0c3d3d32cbcbd212e27842c8b409a720c76ecbcd7daea95b85c",
    "1e0c1c5c22d7768648db97ef8512c137a2be6c318997d65ab7584a1bc9ab1d99320ecd12c9a8a8b7d77eeb55a25bdb9f",
    "9b34e78a7afa8acb8f2d7f462362e099a00b9877848f137560f2c593c31fc50192594067543b0bffd86a5e19e793d66e",
    "9c5d71d280c2f460817443a0a7ae7538fea6420b61f36ca3d142ed9d706aab165adc20721c97d121e01eafc8e48ff1a3",
    "a6502326233e323987e9192387526b6e11467354f7a56dfb54ea9bbff2129dd5009b868445f1d72d8593c4f3bf6d9982",
    "6f19073b8934d30da0cfb8a7d3dd382235770bc767a2f41e9085cf299496f6f7b6cd94666d3b0194608d70ecfd219552",
    "a3018e7393ba41dbb0f87bb9a5e4627784ac8e71e546571c43b5738d8238659e040b7df19f0c0338adc54a30301b82a0",
    "76e649af0dee7e832ffe91530fca5af6a8dee701264c79442197ab2313175f20c8b1568ceb458fdaaee67f29b427aead",
    "f825cf4876a7f3c89437b920d958fca30f9f7633e7b5a36ba992f693cec6b03bac9ff8476a4b8f8152ca7ef860a25702",
    "007c310860cfb4b5b02986d1bd5ffb1bec3e4ba455d48e0bc82a76ff685651c79622de4b01cf3c5ebc893f2538382bf4",
    "e30c2e2dc1c2cf72b4d82e599d55b9a88a5229713208010d91c029722f88e6bce32f57e638cc34d71bb5dd1247975257",
    "ad3e36c2a77d6087972a01c365b429949a6a9759f137b81682cfaf48b2350f1093649f7a3aba889445afdb5278ff7ce4",
    "ce24d431b8b017e37f27bb19e23aa0eb9cd30697d64760f2a94fb9114f5f62f639a079b8ad40fbee389b3a666bb39c06",
    "d8220e9c921c7bea31d6c5fcdd4a8e2ef2bf9e81dc5fdc287c0ebca430507eca720e2b93c3e150aa66c5c770e378a2ef",
    "16ef5dd409d90293f3381be27387770684aa3db358e54469d876a7b34798fb70e2ec96afa37603d5d3e9d6538595d962",
    "16b164e64aa6ab5554bb437ff7157973f661cae49c4996c8ae4ff2dd6665c16acbb6b7275f53204053b9dc40d7db3c30",
    "ef29698537584b9f65c288b26647e46788fac50b5c5526c235e68ce56d4df189bbdb280ceb66a937e8bb4d159c4a56bf",
    "9d6f96d07d4f10c307e9c587814064ef6551d76898c8d1b00b33be085fe37f5a4f9f2c34d83cdef1487cf5b1bf4c38b7",
    "67debd2a4b55e0115abf232a5d411605998826ba506a8ab3af6ad9c8693622a9bf822c3e0f3894198a46a83d47108a51",
    "78c628ac63974680f0e86b4b27c69431509f150e0784473046e2088ffd84d9089138ba533d7957c723e18a3593b51baa",
    "6ed607c1300318ab1a1e9e4f46ef45df09f9eacf6554734fc9e4244a9d5f34cc196ef87ce25ed69b614477388050f5a6",
    "7771239bda287e6c51cb75398c932441a08f082a79d23223fabe7163c23628634c64207a7598c4f96bec3676dc4d47b7",
    "e7d69ccb1d6c1c8f62d281cf479f562eec1d673488e7f92ced419b296837f5654e53801d8f47e3414948bec1c7c8dda4",
    "4469a70833daf710ac5e4db5b3e8e742a9f5946f25f7df687199abfc1b02b22efbe1e847961962a552d56858f9bf907c",
    "4ceada7b2ba06943dd395c354e5497c060ec9f3827b1105f1467cc41ea8bfa3affc88ea41469a4c31e47f901cc9f5b32",
    "894216b817f5bd7e37e3de26e283a9aaefb5bcc33edd15cb8568b01da9470df4e71ec9cf120fd9a9fd1f9bdae37ac7d2",
    "85df387fd21a0d2df9f9bc289474b25b4ba1ab23a11926d3d877ef1a2c2f89c551be69f0448eea0aa54b9c7e89f0119a",
    "dd7e1566c7752607e0ef019f3f702f10f055cedd4d4bfb9bc53924e76a510522db5cd33cbca96b1a9159d0be47ff36c2",
    "3a0ac4312642a42913e540588862222056fb89365a5349dbc9a4a8dfa3af7b191c97c792c3b9d83b1670cc3f505aa5b6",
    "071195a340752506b9462d06dc696ae1a8f0f52066dbe4ec2ea19e054e6826eddd61f22fd99a15392f9aba2b17561182",
    "efa61ec464c38a9f636988a3ec9ff1f96eede69efe72d46a5e7008c8f707edd0db1d15265aa651f123a64f7caee42956",
    "86d8b83c5213232713ce2e3f86483df30302b6f755ce92b7140ce9ab1ce32e113cc3a83fc87272c7707050fa56ace2a8",
    "63665a785de1c2d92769285dba9534d82c844bf5cc3c17aa9712dbef50a580ed4998549ae863c8e8170e7ab967538410",
    "b010ebc9d20e2a9ff4cb495f091914895624a0ae043726dc3ee95e4dbeaae1fb5f670d3f6b0e6a324fb58b1b3aefa80c",
    "1f512a0c446a0cc80f5bc8c77654b3e34c409f53bf15886cddb0b12b818ebc829d390df8a55ac16eeeaa0109001ab852",
    "bf0fdd72c5a7e8a9338e6edce13ef4b8a223ff76070e2931e70ae89eb48f2f93833272398ab5b4bdf57299ddd998408a",
    "ad0c1691a3dd0e63e72551bced4de73c1418d87320161ac78c825ebf15af2ab8fec5ddce8376f9be16637a252e048f51",
    "2f44aee9f630fe699a2df1de0ecf6ddb21d992b4ec952dae9c2a614d5aab5b553baf375c65f4f93e81e2479064b8da1a",
    "6d2c6bd57c5a5178e252976b67e8e9c7be76798e35843651f7dd24c74c9e301aa7dda9cfa4581a39015c294823422404",
    "ffc39430683e1ca335d6d3d55c6257c0c63dd3623cd252b2925ec52be781892f5b23f7ed3a7eec3ef6296d795d67125b",
    "70095d9f1c25dc5eb040b92bfca1957f90f231e210780de10019b41c6a062b085272804fe424638e80b1d91ee4db190a",
    "cd367fab482dce8bcf5619971114c9ff1dc1874c2c6af150c2db4d6242d17d8c1dafb32dea0460976687cdcdd565d9c9",
    "98fa194a90b6437ab2d752b06711d86b32f70baa85125752f90845071be6630725153b88c45c21ec13351974b696a219",
    "aae110b65434328f27445009a176bd164e9fe5cd7f017f9f2fec9e7629088dedd7a1e3c4311f6c0e0c2405aaf1c92300",
    "528ffc3c1d9590114e8dcfe9a5ab0e"
);

/// A `KAS\x03` container, the layout before `KAS\x04`: magic(4), len(2),
/// nonce(12), ciphertext, tag(16). No salt field: its key comes from the
/// fixed PBKDF2 salt "KasSigner-KSPT-v1". Read forever, never written.
const REAL_LEGACY_KSPT: &str = concat!(
    "4b41530326017a6abc8f733bae5e9c419cbdbc0ef063e7baf1a4dcc25e866a4d424c8dd5769d980abc16591bd31d7a7f",
    "3f01160ae9d9e09100a1ceb32216ab91834623c310a3e553ba715304fdbfa9888363c158509710eb2ed61fa7e2e9d959",
    "7909e7a8bc45c6bf737246ba6204e3962be50dac4c970eda4f58503c75bfb760b8f7e5dd7f416ca1723e50f6efdfc01c",
    "533bb1900f9e7c669fef7afdf56aed9b0c6ae34f6a744584163875ee95e3e3d04d7ce295df0221e6c5d8ae9aa76d597c",
    "6355a0308fadb9064c483afd18986f4482e0f3ca0c3faf17d54260250be304a0b8f54d24d59365a3aec24edec4b897f4",
    "0d20c408793e724e60eee55f89457db7d753a4c0c42516187a78dc5a3ee1983cd426f4b1757a1b8816903236925da050",
    "2df56e30089ddec3121e1a5215a09b29b53b859b50ba40b93bba6d700b052f69f90606ed324c5dd5"
);

const REAL_PASSWORD: &[u8] = b"abc";

/// A container a unit wrote opens: the two halves agreeing with each other
/// is not the same as agreeing with a unit.
#[test]
fn a_real_container_opens() {
    use kassigner_crypto::container::open;
    use kassigner_protocol::container::{parse, Layout, Purpose};

    let file = unhex(REAL_V1);

    // What level 1 reads before any key exists.
    let c = parse(&file).expect("level 1 parses a real file");
    assert_eq!(c.layout, Layout::V1);
    assert_eq!(c.purpose, Purpose::Kspt);
    assert_eq!(c.len, file.len() - 53, "header 25 + nonce 12 + tag 16");

    // And what level 2 does with it.
    let mut out = vec![0u8; c.len];
    let opened = open(&file, REAL_PASSWORD, &mut out, None).expect("a real card must open");
    assert_eq!(opened.len, c.len);
    assert_eq!(opened.purpose, Purpose::Kspt);

    // A transaction, checked by its wire magic, not its bytes. `Purpose::Kspt`
    // says what the file is for, not its wire format: this one holds a PSKB
    // bundle.
    let magic = &out[..4];
    assert!(
        magic == b"PSKB" || magic == b"KSPT",
        "not a transaction: {:?}",
        core::str::from_utf8(magic)
    );
}

/// A wrong password on a real file fails, rather than half-working.
#[test]
fn a_real_container_refuses_a_wrong_password() {
    use kassigner_crypto::container::{open, OpenError};

    let file = unhex(REAL_V1);
    let mut out = vec![0u8; file.len()];
    assert_eq!(
        open(&file, b"abd", &mut out, None).err(),
        Some(OpenError::Authentication)
    );
}

/// The oldest layout opens with its key derived in steps, as a board does
/// to show a progress bar: the stepped key from the fixed salt equals the
/// one-call key and opens the file to the same bytes.
#[test]
fn the_oldest_layout_opens_with_the_stepped_key() {
    use kassigner_crypto::container::{
        derive_key, open, open_with_key, KdfParams, Pbkdf2Steps, PBKDF2_ITERATIONS,
    };
    use kassigner_protocol::container::{parse, Purpose};

    let file = unhex(REAL_LEGACY_KSPT);
    let mut steps = Pbkdf2Steps::fixed(REAL_PASSWORD);
    assert_eq!(steps.key(), None);
    let mut last = (0, 0);
    for batch in [1, 999, 37_000, 70_000] {
        last = steps.step(batch);
    }
    assert_eq!(last, (PBKDF2_ITERATIONS, PBKDF2_ITERATIONS));
    let key = steps.key().expect("every round done");
    let whole = derive_key(
        KdfParams::Pbkdf2Sha256Fixed,
        REAL_PASSWORD,
        Purpose::Kspt,
        None,
    )
    .unwrap();
    assert_eq!(key, whole);

    let c = parse(&file).unwrap();
    let mut stepped = vec![0u8; c.len];
    let n = open_with_key(&c, &key, &mut stepped).unwrap().len;
    let mut once = vec![0u8; c.len];
    let m = open(&file, REAL_PASSWORD, &mut once, None).unwrap().len;
    assert_eq!(stepped[..n], once[..m], "the same bytes");
    let other = Pbkdf2Steps::fixed(b"abd");
    assert!(other.key().is_none(), "a fresh one gives no key");
}

/// The oldest layout opens. `KAS\x03` is four bytes of magic and a length:
/// no version, purpose, `kdf_id` or salt. Its key comes from a salt fixed
/// for every file, so one table of guessed passwords opens them all. Read
/// forever, never written.
#[test]
fn the_oldest_layout_opens() {
    use kassigner_crypto::container::open;
    use kassigner_protocol::container::{parse, Kdf, Layout, Purpose};

    let file = unhex(REAL_LEGACY_KSPT);
    assert_eq!(
        &file[..4],
        &[b'K', b'A', b'S', 0x03],
        "the fixture is the layout it claims"
    );

    let c = parse(&file).expect("the oldest layout parses");
    assert_eq!(c.layout, Layout::LegacyNoSalt);
    assert!(c.salt.is_none(), "this layout has no per-file salt");
    assert_eq!(c.kdf, Kdf::Pbkdf2Sha256Fixed);
    assert_eq!(
        c.purpose,
        Purpose::Kspt,
        "implied: the format has no purpose byte"
    );

    // Framing, confirmed against the file itself.
    assert_eq!(c.aad.len(), 6, "magic 4 + len 2");
    assert_eq!(
        file.len(),
        18 + c.len + 16,
        "magic 4, len 2, nonce 12, then tag 16"
    );

    let mut out = vec![0u8; c.len];
    let opened = open(&file, REAL_PASSWORD, &mut out, None).expect("a real old card must open");
    assert_eq!(opened.layout, Layout::LegacyNoSalt);

    let magic = &out[..4];
    assert!(
        magic == b"PSKB" || magic == b"KSPT",
        "not a transaction: {:?}",
        core::str::from_utf8(magic)
    );
}

/// Real files, the current layout and the oldest, are checked in place:
/// each verifies under its password and not under another. Keys come from
/// what each header asks for, as a unit derives them before writing over a
/// file.
#[test]
fn real_containers_are_checked_in_place() {
    use kassigner_crypto::container::{check_with_key, derive_key, KdfParams, OpenError};
    use kassigner_protocol::container::{parse, Layout};

    for (hex, layout) in [
        (REAL_V1, Layout::V1),
        (REAL_LEGACY_KSPT, Layout::LegacyNoSalt),
    ] {
        let file = unhex(hex);
        let key = |password: &[u8]| {
            let c = parse(&file).unwrap();
            derive_key(KdfParams::of(&c).unwrap(), password, c.purpose, None).unwrap()
        };
        let mut copy = file.clone();
        let opened = check_with_key(&mut copy, &key(REAL_PASSWORD)).expect("its own password");
        assert_eq!(opened.layout, layout);
        assert_eq!(opened.len, parse(&file).unwrap().len);
        let mut copy = file.clone();
        assert_eq!(
            check_with_key(&mut copy, &key(b"abd")).err(),
            Some(OpenError::Authentication),
            "{layout:?}"
        );
    }
}

/// Nothing can write the oldest layout or its derivation: `seal` writes only
/// `KAS\x06`, and its header names the derivation and the salt the key came
/// from.
#[test]
fn the_oldest_layout_cannot_be_written() {
    use kassigner_crypto::container::{seal, SealKdf};
    use kassigner_protocol::container::{file_size, parse, Kdf, Layout, Purpose};

    let mut out = vec![0u8; file_size(16)];
    seal(
        Purpose::Kspt,
        &[0u8; 16],
        b"A-card-password-1",
        &[0x11; 16],
        &[0x22; 12],
        SealKdf::Pbkdf2Sha256,
        &mut out,
    )
    .expect("seal");
    let c = parse(&out).unwrap();
    assert_eq!(c.layout, Layout::V1);
    assert_eq!(c.kdf, Kdf::Pbkdf2Sha256, "the derivation it was asked for");
    assert!(c.salt.is_some(), "and it records the salt it derived from");
}
