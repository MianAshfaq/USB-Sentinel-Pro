# Changelog

## 1.10.3 - 2026-07-13

- Reduced the total large-disk fast Defender gate from 24 to 8 focused launch-file checks, divided across connected partitions.
- Preserved the full-scan recommendation for large storage; the fast gate is a bounded pre-access safety check.
- Clarified cancelled operations so they are reported as cancelled and fail closed instead of appearing as an unexplained security failure.

## 1.10.2 - 2026-07-13

- Divides the fast-gate target budget across all connected partitions instead of applying the full budget to every drive letter.
- Keeps files larger than 128 MB under mandatory Defender real-time protection rather than delaying USB approval while unpacking large installers.
- Limits a two-partition external disk to 12 focused pre-access targets per partition while retaining 24 targets for a single-volume device.

## 1.10.1 - 2026-07-13

- Replaces the unrelated full-computer quick scan with focused Defender checks on the connected USB volumes.
- Prioritizes USB root, download, desktop, and document launch files while excluding old Windows installation folders from the fast gate.
- Reduces separate Defender process launches from 250 to 24 per large volume for a substantially faster approval path.
- Requires Microsoft Defender real-time protection to be active so files remain protected after fast-gate access is approved.

## 1.10.0 - 2026-07-13

- Fixes the false Enabled state followed by `Security operation failed` after a delayed USB device removal event.
- Restarts only the physical USB disk after a clean scan instead of also restarting its parent enclosure or bridge.
- Requires approved drive letters to remain accessible after the controlled refresh settles before announcing access.
- Removes the unnecessary enclosure restart that could request a system reboot and add more than 10 seconds per enable.

## 1.9.9 - 2026-07-13

- Enables clean USB drives as soon as Windows reports them accessible after the controlled device refresh.
- Replaces the fixed post-scan delay and repeated WMI discovery with 150 ms readiness checks and a safe timeout fallback.
- Shows a clear finalizing-access state between a successful Defender scan and Explorer access.

## 1.9.8 - 2026-07-11

- Fixed repeated scan/disable loop caused by Windows remove/insert events during the service's own USB device refresh.
- Suppresses planned USB hardware and volume events while access is being refreshed after a clean scan.
- Keeps approved drive state stable after the USB disk restart required for Explorer access.

## 1.9.7 - 2026-07-10

- Fixed malformed `icacls` access-grant command for drive roots such as `E:\`.
- USB access now remains blocked if the post-scan Windows user ACL repair fails.
- Refreshes the USB disk device after ACL repair so Explorer receives the new access state.
- Added tests for detecting failed `icacls` output even when the process exit code is zero.

## 1.9.6 - 2026-07-10

- Fixed clean USB scans where LocalSystem could scan the drive but the requesting Windows user still could not open it in Explorer.
- The desktop now sends the requester SID during Enable USB.
- After a clean scan, the service grants that user Modify access on the USB drive root using Windows ACLs.

## 1.9.5 - 2026-07-10

- Added strict drive-readiness checks before scanning and before showing USB access enabled.
- Added enabled-state access auditing every 10 seconds so stale access states are corrected quickly.
- Cleaned stale Windows mount points during controlled USB enable before automount and device rescan.

## 1.9.4 - 2026-07-10

- Fixed clean scans reporting access enabled while Windows still denied Explorer access.
- Clearing USB access now removes removable-storage deny policy values instead of writing disabled deny values.
- Re-enabled Windows automount during controlled USB enable.
- Added final filesystem-access verification before the dashboard can show USB access enabled.

## 1.9.3 - 2026-07-10

- Fixed invalid `:\` scan targets created when Windows reports USB partitions with no mounted drive letter.
- Added strict drive-root validation so Defender receives only valid roots such as `E:\`.

## 1.9.2 - 2026-07-10

- Fixed mounted portable USB HDD/SSD volumes that Windows reports as fixed or UASP/SCSI media.
- Added Windows storage-bus detection so USB-bus disks are scanned even when they are not marked removable.
- Added adaptive Defender scanning: small USB media use a full custom scan, large USB storage uses a faster safety gate for high-risk launch files.
- Updated access wording to distinguish configured Defender verification from a full scan of every byte on very large drives.

## 1.9.1 - 2026-07-10

- Fixed USB enable being rejected while background Defender maintenance is running.
- Disabled USB action buttons while an enable, wait, scan, format, or remediation operation is active.
- Added a number-calculation recovery check before administrator password reset.
- Cleaned the password dialog rendering so password fields display correctly.

## 1.9.0 - 2026-07-04

- Added hardware-level USB storage discovery before drive letters are mounted.
- Added support for detecting both USBSTOR flash drives and UASP portable HDD/SSD devices.
- Added dashboard hardware names alongside mounted-volume scan results.
- Added audited administrator-only recovery for forgotten USB enable passwords.

## 1.8.2 - 2026-07-03

- Fixed historical audit entries being replayed as new Windows notifications after reconnecting.
- Suppressed disconnect handling while protection is already disabled with no active USB operation.
- Versioned the service protocol so desktop and service agree on live versus historical events.

## 1.8.1 - 2026-07-03

- Corrected the optional code-signing condition in the GitHub release workflow.

## 1.8.0 - 2026-07-03

- Added faster scan startup by reusing signatures updated within six hours.
- Added independent status rows for every connected USB volume.
- Added volume label, capacity, and filesystem details before formatting.
- Blocks access when Defender signatures are over seven days old or unverifiable after an update failure.
- Added Defender threat-detail audit entries and automatic USB-policy tamper restoration.
- Added optional Authenticode signing for executables and MSI when repository certificate secrets are configured.

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
