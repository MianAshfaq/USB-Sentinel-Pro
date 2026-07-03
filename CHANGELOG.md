# Changelog

## 1.7.0 - 2026-07-03

- Added automatic Defender security-intelligence updates in the Windows Service.
- Checks 30 seconds after service startup and every six hours thereafter.
- Falls back to Microsoft's official MMPC update source when configured sources fail.
- Records update versions, success, offline, and failure results in the local audit log.

## 1.6.2 - 2026-07-03

- Added desktop and tray notifications after formatting or Defender remediation.
- Added an optional password-protected rescan-and-enable prompt after those operations.
- Kept storage blocked until the fresh Microsoft Defender verification passes.

## 1.6.1 - 2026-07-03

- Added explicit exFAT or NTFS selection for each chosen USB volume.
- Clarified multi-drive scanning and Defender-only confirmed-threat removal.
- Preserved separate, guarded workflows for threat remediation and full-volume formatting.

## 1.6.0 - 2026-07-03

- Fixed repeated USB notifications caused by policy-generated WMI events.
- Added USB bus-aware detection for flash drives and portable USB HDD volumes.
- Added password-protected Microsoft Defender remediation for confirmed threats.
- Added guarded quick/full exFAT formatting with typed and final confirmations.
- Added clickable website, GitHub, and Facebook icons beside the developer credit.
- Improved failure reporting and fail-closed state accuracy for advanced operations.

## 1.5.0 - 2026-07-03

- Added persistent system-tray monitoring and USB security notifications.
- Added Font Awesome controls and developer social links.
- Added password creation, verification, change, and lockout behavior.
- Added Defender health status, audit export, refresh, and Security History.
- Added WiX installer terms, desktop shortcut, and completion wizard.
- Fixed dashboard auto-close, service reconnection, log reentrancy, and DPI.
- Redesigned the dashboard, settings, password, and license experiences.
