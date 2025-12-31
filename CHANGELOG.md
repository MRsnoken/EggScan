# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]
### Fixed
- Fixed setup page where the admin creation form was not rendered on fresh installs.


## [v1.2.0] – 2025-12-31
### Added
- Theme support: Default, Dark, Light and Cosmos.
- Frontend refactor: UI split into templates and static assets (CSS/JS).
- Upgrade-safe installer: keeps database and secret key, and backs up old files on upgrade.


## [v1.1.0] – 2025-12-02
### Added
- New dashboard view with summary cards for device statistics (e.g. total devices, online/offline).
- Manufacturer modal: you can now click the manufacturer field to review and edit vendor information directly in the UI when it is missing or unknown.

### Changed
- Improved device list layout so IP, MAC, manufacturer and last seen are shown more clearly on a single line per device.
- Replaced the old global “Sort:” text with clearer per-column descriptions under IP, MAC, manufacturer, etc.
- Scan status now shows which scan loop is currently running and when the next loop will run after changing the scan interval.
- Better handling and display of devices with unknown or missing manufacturer information.
- Internal cleanup in `eggscan.py` (removed leftover comments and unused code paths).

### Fixed
- Column widths and table layout so text is no longer cut off or wrapped in an ugly way.

## [v1.0.4] – 2025-11-24
### Fixed
- Swedish translation updated: the “Last Seen” column header now shows “Senast sedd”.

## [v1.0.3] – 2025-11-24
### Added
- `last_seen_at` timestamp for each device.
- New “Last Seen” column in the UI.

### Changed
- Offline devices now retain their last_seen_at timestamp (IP resets to "-" but last_seen_at remains).
- Scan timestamps now use the system’s local time.

### Fixed
- Database migration for `last_seen_at` is now handled automatically **via the install script** on upgrade.
- IPv6 cleanup properly removes IPv6 addresses when IPv6 discovery is disabled.

## [v1.0.2] – 2025-11-19
### Changed
- Updated IP handling: device IP lists are now rebuilt on each scan, ensuring only addresses detected in the latest scan are stored.
- Replaced checkbox controls with modern toggle switches for a cleaner and more consistent UI.

## [v1.0.1] – 2025-11-16
### Changed
- Added modal dialog for devices with multiple IP addresses (IPv4/IPv6).
- Improved text readability in dialogs (modals use dark text on light background).
- Prevented layout overflow when many IP addresses are shown.
- Bumped internal version to 1.0.1.

## [v1.0.0] – 2025-11-15
### Added
- Initial public release of EggScan.
- Nmap-based network scan for configured subnets.
- Web dashboard with login, user management and basic settings.
- Device list with IP, MAC, alias, manufacturer, ping and status (online/offline).
