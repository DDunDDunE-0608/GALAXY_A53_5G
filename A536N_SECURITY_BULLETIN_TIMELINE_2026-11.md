# SM-A536N security bulletin and firmware timeline update

Updated: 2026-11-21

## Official Samsung bulletin (November 2026)
Samsung's official SMR-NOV-2026 bulletin lists SVE-2026-3546 / CVE-2026-21155:
- Affected Android versions: 14, 15, 16, 17
- Description: Out-of-bounds write in bootloader before SMR Nov-2026 Release 1, physical attacker
- Patch: proper input validation
- Bulletin version: 1.0, Nov 3 2026; CVE list update Nov 5 2026

Samsung's bulletin applies at OS-version/release level, not with a specific SM-A536N firmware mapping.

## SM-A536N official update history (Samsung support changelog)
| Build | Release date | Android | Security patch | Notes |
|---|---|---:|---|---|
| A536NKSUIGZI2 | 2026-09-28 | 16 | 2026-08-05 | Stability fixes |
| A536NKSSIGZH4 | 2026-08-31 | 16 | 2026-08-05 | Security-code fixes |
| A536NKSSHGZE2 | 2026-05-19 | 16 | 2026-05-05 | Security-code fixes |
| A536NKSSGGZD1 | 2026-04-15 | 16 | 2026-04-05 | Security-code fixes |
| A536NKSSFGZC2 | 2026-03-26 | 16 | 2026-03-05 | Security-code fixes |
| A536NKSSFGZB2 | 2026-02-26 | 16 | 2026-02-05 | Security-code fixes |
| A536NKSSEGZA1 | 2026-01-22 | 16 | 2026-01-01 | Security-code fixes |
| A536NKSSDGYL1 | 2025-12-18 | 16 | 2025-12-01 | Security-code fixes |
| A536NKSSDGYK2 | 2025-11-27 | 16 | 2025-11-01 | Security-code fixes |
| A536NKSSCGYI3 | 2025-10-14 | 16 | 2025-10-01 | Security-code fixes |
| A536NKSUCGYI2 | 2025-10-12 | 16 | 2025-09-01 | Android 16 release |
| A536NKSSCFYH1 | 2025-08-21 | 15 | 2025-08-01 | Android 15 build |

## Current assessment
- User's build A536NKSUIGZI2 has Android 16 and Aug-2026 patch; it predates the Samsung November 2026 bulletin.
- The bulletin's broad affected range includes Android 16 and states bootloader vulnerability prior to Nov-2026 SMR.
- **Likelihood of being in the pre-fix vulnerable population: high based on version chronology, but not individually confirmed for SM-A536N/A536NKSUIGZI2.**
- Samsung has not publicly provided a per-model mapping in this bulletin. Exact vulnerable S-Boot component and patch difference for this model remain unverified.
- CVE report describes physical-access threat; vulnerability applicability is not evidence of unlock capability, exploit reliability, or an OEM-unlock state transition.
- No exploit steps, payloads, or runtime validation are included in this report.

## Firmware rollback / binary revision
The current binary revision is 18. Android 15 target build A536NKSSCFYH1 is binary 12. Ordinary rollback from 18 to 12 is expected to be blocked by Samsung anti-rollback; do not attempt it.

## Sources
- Samsung official SM-A536N changelog: https://doc.samsungmobile.com/SM-A536N/022144220325/kor.html
- Samsung official Nov-2026 security bulletin: https://security.samsungmobile.com/securityUpdate.smsb?year=2026&month=11
- Firmware metadata for current build: https://www.sammobile.com/samsung/galaxy-a53-5g/firmware/SM-A536N/KOO/download/A536NKSUIGZI2/2019173/
- SM-A536N firmware history: https://firmwareindex.com/samsung/sm-a536n/

## Confidence
- Current build/patch chronology: high (Samsung changelog).
- Bulletin's vulnerability description and affected Android major versions: high (Samsung official bulletin).
- Exact vulnerability status of A536N current binary: medium / unconfirmed.
- Whether vulnerability could affect unlock or custom-ROM installation: unknown; not asserted.
