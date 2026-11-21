# SM-A536N LineageOS installation prerequisite comparison

Updated: 2026-11-21

## Official device support
The Odd Solutions / LineageOS a53x installation page explicitly lists SM-A536N as a supported model.

## Required pre-install firmware and BL
- Required stock OS: Android 15
- Exact BL version listed for SM-A536N: A536NKSSCFYH1
- The guide requires OEM Unlock enabled in Developer Options, then entering Download Mode and selecting the device-unlock option, followed by a factory reset.
- Guide warns that using a different firmware can fail installation or cause unexpected problems.

## User device
- Model: SM-A536N
- Current BL/build: A536NKSUIGZI2
- Android: 16 / One UI 8
- Binary revision: 18
- OEM Unlock toggle: absent
- Bootloader: locked

## Comparison
| Requirement | Current device | Status |
|---|---|---|
| Exact model supported | SM-A536N | Match |
| Android 15 stock firmware | Android 16 | Mismatch |
| Exact BL A536NKSSCFYH1 | A536NKSUIGZI2 | Mismatch |
| Binary revision compatible with target | 18 vs target 12 | Downgrade barrier expected |
| OEM Unlock enabled | Missing | Blocked |
| Bootloader unlocked | Locked | Blocked |

## Conclusion
LineageOS is officially documented for the model, but the current device does not satisfy installation prerequisites. Ordinary downgrade from binary 18 to target binary 12 is expected to be blocked by Samsung anti-rollback. Do not attempt downgrade or flashing. This does not prove the model can never be unlocked, but no supported unlock path is currently evidenced on this device.

## Source
- Official installation guide: https://wiki.oddsolutions.us/devices/a53x/install/
- Samsung firmware update history: https://doc.samsungmobile.com/SM-A536N/022144220325/kor.html
- Current build metadata: https://www.sammobile.com/samsung/galaxy-a53-5g/firmware/SM-A536N/KOO/download/A536NKSUIGZI2/2019173/
