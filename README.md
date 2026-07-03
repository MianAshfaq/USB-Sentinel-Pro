# USB Sentinel Pro

Defensive Windows 11 software that keeps removable USB storage blocked by
default, requires a password before enabling access, scans removable drives
with Microsoft Defender, and blocks storage again after disconnection.

**Developed by Muhammad Ashfaq**

[Website](https://cyberoly.com) | [GitHub](https://github.com/MianAshfaq) |
[Facebook](https://fb.com/MianAshfaq012)

## Features

- LocalSystem Windows Service for privileged USB policy operations.
- Password required for every USB-enable request.
- Salted PBKDF2-SHA256 password verifier with failed-attempt lockout.
- Microsoft Defender signature updates, custom scans, and remediation results.
- Background Defender signature checks at startup and every six hours, with official Microsoft MMPC fallback.
- WMI USB insert/remove monitoring with event deduplication and automatic fail-closed blocking.
- USB bus-aware discovery for flash drives and mounted portable HDD volumes.
- Password-protected Defender remediation and guarded exFAT/NTFS formatting tools.
- Post-remediation and post-format prompts to rescan and enable only when clean.
- System-tray monitoring after the dashboard is closed.
- Female Windows voice preference, voice test, and state announcements.
- Defender health/signature status, audit export, and Security History access.
- SQLite settings and security-event storage under `%ProgramData%`.
- Administrator-only versioned named-pipe communication.
- Desktop and Start Menu shortcuts with a branded icon.

## Projects

- `UsbSentinel.Desktop`: .NET 8 WPF dashboard and tray application.
- `UsbSentinel.Service`: LocalSystem Windows Service.
- `UsbSentinel.Contracts`: versioned service protocol and shared models.
- `UsbSentinel.Tests`: protocol and security-invariant tests.
- `installer`: WiX 5 per-machine MSI with license wizard.

## Requirements

- Windows 11 x64, version 22H2 or later.
- Microsoft Defender Antivirus available and active.
- Administrator access for installation and dashboard control.
- .NET 8 SDK only when building from source; the installer is self-contained.

## Install

Download `USB-Sentinel-Pro-Setup.msi` from GitHub Releases and run it as
Administrator. Accept the MIT license terms and complete the installer.

On first launch, create a password with at least eight characters, one letter,
and one number. This password is required every time USB storage is enabled.
The plaintext password is never stored or written to logs.

Closing the dashboard keeps monitoring active in the Windows system tray.
Double-click the tray icon to restore the dashboard. Use the tray menu's Exit
command when you intentionally want to stop the desktop client. The Windows
Service continues enforcing USB policy independently.

## Build

Open `USB Sentinel Pro.sln` in Visual Studio 2022, or run:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\scripts\build.ps1
```

The build restores packages, runs tests, publishes self-contained Windows x64
binaries, and creates `artifacts\installer\USB-Sentinel-Pro-Setup.msi`.

## Security Model

- All registry, device, Defender, WMI, and SQLite operations run in the service.
- The named pipe permits only LocalSystem and local Administrators.
- Service startup, shutdown, cancellation, scan failure, and device removal use
  fail-closed storage policy.
- Defender performs malware detection and remediation; the app never directly
  deletes user files.
- Formatting is intentionally destructive and requires a selected USB volume,
  password, typed drive confirmation, and final warning. Quick format is not
  secure erasure and no antivirus can guarantee detection of every threat.
- "Block all USB devices" restricts new unspecified device installations. It
  deliberately does not retroactively disable existing keyboards and mice.

## Platform Limitation

Registry and Group Policy controls cannot let Defender read a mounted volume
while simultaneously denying that volume to every other administrator process.
Strict pre-scan process isolation requires a signed kernel minifilter or an
enterprise device-control product. USB Sentinel Pro does not claim kernel-level
scan isolation.

## Privacy

The application has no advertising, analytics, or telemetry upload code. Local
logs, settings, and password-verifier data remain under
`%ProgramData%\USB Sentinel Pro`.

## Contributing

Contributions are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md) and
[SECURITY.md](SECURITY.md) before opening a pull request or security report.

## License

USB Sentinel Pro is free and open-source software licensed under the
[MIT License](LICENSE). See [TERMS.md](TERMS.md) for the defensive-use and
operational notices shown by the installer.
