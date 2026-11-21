# SM-A536N applicability review: CVE-2026-21155 / SVE-2026-3546

Updated: 2026-11-21
Scope: defensive, read-only applicability assessment. No PoC execution, payload construction, flashing, or device modification.

## Official Samsung bulletin
Samsung's November 2026 Security Maintenance Release 1 bulletin lists SVE-2026-3546 / CVE-2026-21155:
- Affected Android versions: 14, 15, 16, 17
- Description: out-of-bounds write in bootloader before SMR Nov-2026 Release 1; physical attacker; patch adds proper input validation.
- Samsung's bulletin is a release-level statement, not a model-by-model affected-build list.

## User's SM-A536N state
- Model: SM-A536N
- BL/build: A536NKSUIGZI2
- Android: 16
- Security patch level: 2026-08-05 (user reported; Samsung update page lists the build with this patch level)
- Current firmware is earlier than the November 2026 SMR bulletin/fix release.

## Applicability assessment
- The device/build is within the bulletin's broad Android-version range (Android 16).
- Its reported August 2026 security patch predates the November 2026 fix.
- Therefore it is **plausibly within the affected pre-fix population**, but Samsung's public bulletin does not identify SM-A536N or A536NKSUIGZI2 as individually affected, and the exact S-Boot patch status has not been established by a binary comparison.
- Do not infer practical exploitability, bootloader unlock, or a bypass from this bulletin.
- The public researcher's device validation was on Galaxy S25 FE (SM-S731U1), not this A536N; it cannot substitute for exact-model validation.

## Safe next verification
1. Track Samsung's SM-A536N update history for an update with the November 2026 or later security patch.
2. If a new official firmware becomes available, compare public metadata and build/hash information only; do not flash solely for this research.
3. A precise patch determination would require a vendor-confirmed model/build mapping or a controlled read-only comparison of the relevant stock binaries. No exploit details or runtime tests are in scope.

## Sources
- Samsung November 2026 bulletin: https://security.samsungmobile.com/securityUpdate.smsb
- Samsung SM-A536N firmware changelog: https://doc.samsungmobile.com/SM-A536N/022144220325/kor.html
- Public writeup (testing on SM-S731U1 only): https://github.com/UnsignedChad/CVE-2026-21155-SVE-2026-3546
