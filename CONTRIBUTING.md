# Contributing to scan4all

Thank you for your interest in contributing to scan4all! This project is a
vulnerability scanner built in Go that integrates `vscan`, `nuclei`,
`ksubdomain`, `subfinder`, and other tools.

## Getting Started

1. Fork the repository on GitHub.
2. Clone your fork locally:
   ```sh
   git clone https://github.com/<your-username>/scan4all.git
   cd scan4all
   ```
3. Add the upstream remote:
   ```sh
   git remote add upstream https://github.com/GhostTroops/scan4all.git
   ```

## Requirements

- Go 1.18 or later.
- `libpcap-dev` for network scanning features.
- `nmap` for fast port scanning (optional).

## Reporting Bugs

Before submitting a bug report, please:

- Check the [issues](https://github.com/GhostTroops/scan4all/issues) for similar reports.
- Collect the exact command used and the full output/logs.
- Include the scan4all version, operating system, and Go version.

## Submitting Changes

- Use clear, descriptive commit messages.
- Run `gofmt -w` on modified Go files before committing.
- Add unit tests where appropriate.
- Update documentation in `static/` when changing behavior.

## Code Style

- Follow standard Go formatting (`gofmt`).
- Keep functions focused and readable.
- Prefer English for all comments and user-facing strings.

## Translation Guidelines

- All code comments and user-facing strings should be written in English.
- Use American English spelling.
- Keep technical terms such as POC, CVE, and protocol names in their standard form.

## License

By contributing, you agree that your contributions will be licensed under the
project's [MIT license](LICENSE).
