# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

## [1.8.2] - 2026-07-25

### Added
  -  Updater progress modal on the About page with done, running, pending and error checklist states.
  -  Admin-only About page note pointing to the full updater history log.

### Changed
  -  About page updater is disabled on non-Debian/systemd systems and README now documents that support limit.
  -  About page updater log now shows only the latest updater run while the full history remains in `/var/log/eggscan-update.log`.
  -  About page install information no longer shows the internal `version.json` path.

### Fixed
  -  Stale updater reload prompts no longer remain visible on the About page after an update.

## [1.8.1] - 2026-07-23

### Changed
  -  Updater status now refreshes automatically after starting an update and shows a reload hint when the update is complete.

## [1.8.0] - 2026-07-23

### Added
  -  About page showing installed version, install paths and runtime details.
  -  Admin-only update check on the About page using the latest GitHub release.
  -  Admin-only updater on the About page with start control, status and latest log output.

### Changed
  -  Installer now creates a dedicated `eggscan` system user/group and runs the web UI service as that user instead of root.
  -  Scan worker service now runs as the dedicated `eggscan` user with limited network capabilities for scanning.

### Fixed
  -  Scan requests now work with older databases even if the `settings.key` unique index is missing.
  -  Nmap host discovery now requests privileged scan mode when running under the hardened scan worker service.

## [1.7.0] – note set yet 

## Added
  -  Quick tag filters on the index page (`All` + admin-defined quick tags).
  -  Quick-tag chip counts (for example `iot (12)`).
  -  Admin quick-tag manager (collapsible panel) with autocomplete from existing device tags.
  -  Config snapshot export/import in Settings for backup/transfer of existing app configuration only.
  -  Export popup for config snapshots where you choose which configuration sections to include.
  -  Extra offline verification pass for known devices before they are marked offline.
  -  Per-device offline reminders, disabled by default, with a configurable repeat interval.
  -  Uplink theme with terminal-inspired network console styling.
  -  New devices dashboard counter opens a compact review modal with the existing device actions.
  -  Settings search to quickly filter configuration sections.

## Changed
  -  Active quick-tag filter is now stored in URL query (`?tag=`) so refresh/share keeps the same view.
  -  Manual `Scan now` keeps the current page filter state (including quick-tag selection) after redirect.
  -  Quick-tag removal now supports direct remove via `×` with confirmation (no extra save click needed).
  -  Pressing `Enter` when adding a quick tag now saves immediately; save button remains available.
  -  Config snapshot import now follows the snapshot file content (selected at export time) and remains backward compatible with older snapshots.
  -  Dark theme now uses a cleaner high-contrast dark palette.
  

## Fixed
  -  Offline alerts are no longer retried every scan when an existing alert log entry for the same offline event has status `failed`.

## [1.6.0] – 2026-02-08

## Added
  -  Multi-channel alert providers via Apprise (Discord, Telegram, Slack, Email, Teams, Pushover, Gotify, Custom).
  -  Provider-specific alert fields in settings with a unified enable toggle.
  -  Backward compatibility for existing Discord webhook settings.
  -  Quiet hours with digest summary after quiet period ends, including event timestamps.
  -  Admin action to mark all new devices as known with one click.
  -  Database backup download button in Settings (admin only).

## [1.5.2] – 2026-01-26

## Fixed
  -  Added CSRF protection for all POST actions.
  -  Logout is now POST-only (CSRF-protected).
  -  Settings updates are now saved in a single transaction to avoid partial updates.
  -  AJAX errors now surface as flash alerts (mark known, subnet order, scan status).

## Added
  -  Device details (notes) field in the alias modal.
  -  Device tags in the alias modal with search support, autocomplete, and chip input.
  -  Flash messages now auto-dismiss after 15 seconds.

## [1.5.1] – 2026-01-16

## Fixed
  -  Alias updates now persist correctly even when stored MAC addresses use uppercase.

## [1.5.0] – 2026-01-11

## Added
  -  Discord alert integration (optional):
  -  Alerts for new devices.
  -  Alerts for devices appearing in new subnets.
  -  Offline / back-online alerts with configurable thresholds.
  -  Timezone-aware UI display:
  -  All timestamps are stored internally as UTC.
  -  UI can display times in a selectable timezone without affecting stored data.
  -  Manual scan requests now integrate cleanly with the scheduled scan loop.
  -  Scan locking logic to ensure only one scan can run at a time, even if multiple requests occur.

## Changed
  -  Web interface is now served via Gunicorn by default (production-ready setup).
  -  Scanning logic is fully separated from the web UI:
  -  One dedicated scan worker process.
  -  Web UI is read-only with respect to scan execution state.
  -  Manual scans reset the scan interval timer (next scheduled scan runs after the manual scan).
  -  Scan state is now always derived from the database, ensuring consistent results across users.

## Improved
  -  Overall stability under concurrent access (multiple users viewing the UI).
  -  More predictable scan behavior in mixed environments (manual + scheduled scans).
  -  Clearer separation of responsibilities between web service and scan service.
  -  SQLite concurrency tuned for this workload (WAL mode and sane defaults).

## Installation / Upgrade
  -  Fully upgrade-safe:
  -  Existing database and data are preserved.
  -  Schema updates are applied automatically at startup.
  -  No manual migration steps required, even from very old versions.



## [1.4.0] – 2026-01-06

### Added
- Subnet labeling and grouped subnet view.
- Subnets can now be given human-readable labels (e.g. Home, Guest, Lab).
- Labeled subnets can be displayed either:
  - as a column in the device table, or
  - grouped into subnet sections.
- Devices are shown strictly based on where they were observed during the latest scan.
- Devices with addresses in multiple subnets may appear in multiple groups.

### Improved
- Scan result handling for multi-subnet environments is now deterministic and inspectable.
- Database schema initialization and upgrades are handled automatically at startup.

### Installation / Upgrade
- Installer is upgrade-safe:
  - Existing database and secret key are never overwritten.
  - Schema changes are applied automatically on upgrade.
  - Fresh installs and upgrades are detected correctly.

## [1.3.0] – 2026-01-02

### Added
- Automatic device search without requiring the manual “Search” button.
- Egg emoji 🥚 added to the navbar for clearer branding and visual identity.

### Changed
- Improved scan update behavior:
  - Page refresh is deferred while a modal is open or a search filter is active.
  - An “Update” button is shown when new scan results are available.
- “Search” button removed from the UI, while keeping Enter key submission as a fallback.
- Device counters and UI state now update immediately when a device is marked as known, without requiring a full page reload.

### Improved
- Better text contrast and readability:
  - Stronger label colors on `setup.html` and `login.html`.
  - Improved visibility of text inside modules on the index page.
- Smoother and more predictable UI behavior during scans and modal interactions.

## [v1.2.1] – 2025-12-31

### Fixed
- Fixed setup page where the admin creation form was not rendered on fresh installs.
- Fixed installer service start logic on fresh installs (restart now falls back to start).

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
- Database migration for `last_seen_at` is now handled automatically via the install script on upgrade.
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
