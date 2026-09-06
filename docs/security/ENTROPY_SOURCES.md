# Entropy Sources and Credit Policy

KasSigner mixes multiple independent and supplemental observations before BIP39 mnemonic creation. The mixer is designed so that adding an attacker-influenced supplemental input cannot subtract entropy supplied by a healthy trusted source. **Source count is not treated as an entropy estimate.**

## New mnemonic creation

| Input | Role | Requirement / credit policy |
|---|---|---|
| ESP32-S3 WDEV hardware RNG | Primary physical source | Mandatory. Continuous structural health checks must pass. |
| Camera temporal sensor noise | Physical source | Mandatory and liveness/health checked over complete descriptor-bounded captures. Partial/timed-out DVP buffers are rejected; seed creation may retry a fresh eight-capture health window up to three times, but the liveness thresholds are not relaxed. E-12 remains open: KasSigner does not claim a numerical min-entropy value until empirical SP 800-90B characterization is complete. |
| Board IMU gyroscope noise | Physical source | Waveshare QMI8658C is health checked and mixed. CoreS3 BMI270 is configured at boot and at least one complete healthy pre/post-camera window is mandatory for CoreS3 seed creation. |
| SYSTIMER timing observations | Timing/context source | Mandatory usable/diverse observations bracket the checked WDEV sampling loop, preserving loop/interrupt timing variation. “SYSTIMER” and “timing jitter” are one measurement family, not two independent entropy sources. |
| Factory base MAC | Device binding only | Mixed as deterministic per-device context and assigned **zero entropy credit**. |
| `OPTIONAL_UNIQUE_ID` (128-bit eFuse field) | Device binding only | Restored from the original seed path and mixed with an explicit domain separator. It is public/deterministic identity context, receives **zero entropy credit**, and never satisfies a mandatory entropy gate. |
| User idle/touch timing | Supplemental context | Mixed when available; assigned zero guaranteed entropy credit. |
| SAR/ADC observation | Supplemental analog context | Mixed during final whitening; assigned zero guaranteed entropy credit. |
| Manual d6 rolls | User-supplied additive source | Optional during new-mnemonic onboarding (Always Start Fresh or Device-Bound) and mixed only **after** the mandatory hardware/camera/IMU/timing path passes. Standalone Dice Seed remains a separate Seed Tools feature. |
| Deliberate Touch entropy | User-supplied additive source | Optional after the Dice choice for new mnemonic creation. A domain-separated touch digest is mixed only **after** the mandatory hardware/camera/IMU/timing path passes; declining Touch does not alter the already validated staged pool. Standalone Touch Seed remains a separate Seed Tools feature. |

The final pool is repeatedly domain-separated and whitened with SHA-256 and fresh checked hardware-RNG bytes. No deterministic identifier, timer, ADC sample, touch sample, or IMU sample is allowed to replace the mandatory WDEV RNG and camera gates.

## Camera capture boundary

Camera health is evaluated only from complete capture buffers. The shared ESP-HAL DVP acquisition primitive uses a bounded poll of the transfer's completion signal; if that signal never arrives, the transfer is stopped, the partial buffer is rejected, and no camera-health observation is recorded from it. Seed creation evaluates eight-capture health windows and may start a new window after a transient unhealthy result, up to three windows total. Each window starts with a fresh liveness tracker, and a seed is accepted only when one complete window satisfies the unchanged captured-frame, live-delta, and consecutive-stale limits. Retrying acquisition does not convert stale or partial frames into credited entropy.

## CoreS3 BMI270 boundary

The CoreS3 BMI270 requires a vendor configuration upload on every power-up. KasSigner uses an exact-pinned `bmi2` dependency only for that configuration/power-control operation. KasSigner itself owns collection of fresh gyro data, per-axis diversity checks, completeness checks, seed-policy enforcement, domain separation, and zeroization. CoreS3 entropy acquisition keeps the documented 200 Hz normal filter mode but selects the ±250 dps data-register range so ordinary sensor noise remains visible at raw low-byte resolution; this is a health/liveness configuration and does **not** create a numerical min-entropy claim. Failure to initialize or obtain a healthy BMI270 seed window prevents **new CoreS3 mnemonic generation**; it does not block importing/recovering an existing mnemonic or signing with an existing wallet.

## eFuse provisioning

The factory-programmed base MAC and ESP32-S3 `OPTIONAL_UNIQUE_ID` do not require KasSigner Secure Boot/HMAC provisioning. Both are retained only as deterministic device binding and receive **zero entropy credit**. `OPTIONAL_UNIQUE_ID` is mixed whether programmed or all-zero; either case is harmless deterministic context and cannot satisfy a mandatory source gate. Future provisioned *secret* eFuse/HMAC material requires a separate lifecycle and threat-model review before any entropy credit is assigned.
