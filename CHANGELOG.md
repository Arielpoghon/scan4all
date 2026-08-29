# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The project has been translated into English to improve accessibility for the
global security research community. The translation scope includes:

## [Unreleased]

### Added
- Full English translation of the README and all documentation under `static/`.
- English translations for comments, log messages, and user-facing strings across
  all Go source packages (`pocs_go`, `pocs_yml`, `webScan`, `pkg`, `lib`, `brute`,
  `engine`, `spider`, and more).
- `CONTRIBUTING.md` and `CHANGELOG.md` documentation files.

### Changed
- Renamed the Chinese README to `README_CN.md` and linked it from the main README.

### Fixed
- Removed stray `__pycache__` artifacts from the `tools/` directory.
- Added `__pycache__/` to `.gitignore`.
