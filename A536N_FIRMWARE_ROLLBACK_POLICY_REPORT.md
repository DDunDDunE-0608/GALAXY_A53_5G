# SM-A536N Firmware / Anti-Rollback Review (Read-only)

Updated: 2026-11-21

## Scope
Compare the user's current firmware with the Android 15 firmware cited by the a53x custom-ROM install guide. This is a metadata/release-history review only. No firmware was flashed and no device state was changed.

## Confirmed user-device state
- Model: SM-A536N
- Current BL/build: A536NKSUIGZI2
- Android: 16 / One UI 8
- OEM Unlock toggle: absent (user observation)
- Bootloader state: locked (user-provided properties and Download Mode observation)

## Firmware comparison
| Build | Android | Binary / SW revision | Release listing |
|---|---:|---:|---|
| A536NKSSCFYH1 | 15 | C / 12 | 2025-08-04 |
| A536NKSUCGYI2 | 16 | C / 12 | 2025-09-18 |
| A536NKSSCGYI3 | 16 | C / 12 | 2025-09-29 |
| A536NKSSDGYK2 | 16 | D / 13 | 2025-11-27 |
| A536NKSSDGYL1 | 16 | D / 13 | 2025-12-03 |
| A536NKSSEGZA1 | 16 | E / 14 | 2026-01-08 |
| A536NKSSFGZB2 | 16 | F / 15 | 2026-02-13 |
| A536NKSSFGZC2 | 16 | F / 15 | 2026-03-09 |
| A536NKSSHGZE2 | 16 | H / 17 | 2026-05-06 |
| A536NKSSIGZH4 | 16 | I / 18 | 2026-08-20 |
| A536NKSUIGZI2 | 16 | I / 18 | 2026-09-14 (listing date) |

Notes: Samsung firmware revision letters are shown as reported by third-party firmware indexes; the current build is consistently listed as binary 18. The Android-15 guide target is binary C (12), which is far below the user's currently fused/revision level I (18).

## Assessment
1. The cited Android-15 target A536NKSSCFYH1 is not a viable ordinary downgrade target from the current binary-18 device. Standard Samsung flash validation is expected to reject lower binary revisions (SW REV CHECK FAIL). **Do not attempt a downgrade.**
2. This establishes a practical firmware-version barrier; it does not establish that OEM unlocking is permanently unavailable on all A536N firmware, nor does it prove any vulnerability.
3. The user's missing OEM Unlock control and locked Download Mode currently prevent the supported unlock flow.
4. No evidence found in this review that a firmware update/downgrade alone would restore OEM Unlock.
5. A future research conclusion should be based on exact model/build-specific official evidence, not chipset-family vulnerability claims.

## Sources
- Samsung model support page: https://www.samsung.com/sec/support/model/SM-A536NZWAKOC/
- SamMobile SM-A536N firmware history: https://www.sammobile.com/samsung/galaxy-a53-5g/firmware/
- SamFirm current firmware and binary revision: https://samfirm.shop/model/SM-A536N
- SamFW Android-15 target A536NKSSCFYH1 (Binary C / 12): https://samfw.com/firmware/SM-A536N/KOO/A536NKSSCFYH1
- FindMyROM firmware package listing: https://findmyrom.com/devices/samsung-sm-a536n

## Confidence
- Exact current build and device lock state: high (user-observed).
- Current binary 18: high (multiple firmware indexes agree).
- Target build binary C / 12: high (firmware metadata).
- Downgrade rejection from binary 18 to 12: high as standard Samsung anti-rollback behavior, but not experimentally tested on this device.
- Whether a different firmware could expose OEM Unlock: unknown.
- Whether a vulnerability applies to this exact BL: unknown.

## Next read-only research
Compare the release metadata and available patch notes for the BL/security-related changes across the firmware timeline. Do not download/flash older packages, modify the phone, or run exploit code.
