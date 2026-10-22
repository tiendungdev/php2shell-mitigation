# php2shell-mitigation

Temporary mitigation for php2shell (CVE-2026-109618 / CVE-2026-109619) on Ubuntu
and AlmaLinux 8, including FastPanel 2 hosts whose PHP builds under `/opt` are not
updated by apt/dnf.

- `php2shell-mitigate.sh` — `--status`, `--dry-run`, `--apply`, `--revert`
- `HUONG-DAN.md` — full guide (Vietnamese), including the quick-start download over SSH

This is a stopgap. Install the vendor PHP fix as soon as one exists.
