# GuardMGR

Self-hosted server security scanning for your whole fleet. GuardMGR is a
ScriptGain product: a control-plane panel plus polling agents that run scheduled
security scans on each server and report findings and a hardening score back to
one dashboard.

- **Master panel** — Laravel control plane (auth, roles, settings, licensing,
  self-update, firewall/host-SSL, API).
- **Agent** — a small Go binary enrolled per server; it polls the master for
  work, runs the scan, and posts results. (Scan engines land in Phase 2.)
- **Scans** — a scan is a scheduled job whose result is a set of findings
  (severity, title, detail, engine) and a 0–100 hardening score.

> Phase 1 is the platform skeleton (forked from the BackupMGR base): panel,
> auth, licensing, agent enrollment, scan-job scheduling, and the scan/findings
> data model. The scan engines (Lynis, rkhunter, ufw) are Phase 2.

## Licensing

Self-hosted installs validate their license against `scriptgain.com`. Set a key
with `php artisan guard:license <key>` or from **Settings → License**.
Enforcement is lenient and never locks the panel.

## Stack

Laravel + Tailwind (browser CDN) + Alpine on the master; Go for the agent;
MariaDB/MySQL or SQLite.
