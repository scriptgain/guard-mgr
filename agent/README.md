# GuardMGR Agent

The host-side agent for [GuardMGR](https://scriptgain.com/products/guardmgr).
It enrolls with a GuardMGR master, runs security scans on a schedule, reports
findings back, and can apply remediations the master asks for.

This repository is the **source** for the agent binary we distribute. It is
private and the source is not shipped to customers. Customers receive a compiled
binary served by their own master.

The agent only ever dials **out** to the master over HTTPS. It opens no inbound
ports and works behind any NAT or firewall.

## Install (customer-facing)

Customers do not clone this repository. They create a host in the GuardMGR panel
and run the install command it shows, which enrolls and registers the service in
one step:

```sh
guard-agent enroll -master https://guard.example.com -token <ENROLL_TOKEN>
```

`enroll` auto-installs the systemd service, so no separate `install` call is
needed in the normal path.

## Scanners

Each scanner is skipped cleanly when its underlying tool is not present on the
host, so a partial toolchain still produces a useful report.

| Scanner | What it covers |
|---|---|
| `lynis` | System hardening audit |
| `rkhunter` | Rootkit detection |
| `chkrootkit` | Rootkit detection, second opinion |
| `maldet` | Linux Malware Detect |
| `clamav` | Antivirus scan |
| `fail2ban` | Jail status and ban activity |
| `ufw` | Firewall state and rules |
| `updates` | Pending OS security updates |
| `wordpress` | WordPress core, plugin, and theme exposure |

## Remediation

The master can ask the agent to act on a finding rather than just report it:

- `FixFinding` applies the remediation for a specific finding.
- `RunUpdates` installs pending OS updates.

Remediation is driven by the master, so it is auditable centrally instead of
being decided host-side.

## Subcommands

```
guard-agent version
guard-agent enroll -master <url> -token <token>   (auto-installs the service)
guard-agent install                               (install + enable systemd service)
guard-agent uninstall                             (disable + remove systemd service)
guard-agent run
```

## Service and paths

| Item | Path |
|---|---|
| Installed binary | `/usr/local/bin/guard-agent` |
| systemd unit | `/etc/systemd/system/guard-agent.service` |
| Config | `~/.config/guard/agent.json`, honoring `XDG_CONFIG_HOME` |

Override the config path with `GUARD_CONFIG` or `-config`. The service runs as
root because the scan tooling requires it.

`install` is idempotent: re-running it refreshes the unit and restarts the
service.

## Self-update

Updates are downloaded over HTTPS and verified before they are swapped in, so a
tampered or MITM'd download is rejected and the running binary is left in place.

## Build

```sh
./build.sh 0.5.0
```

Produces a fully **static** Linux x86_64 binary. `CGO_ENABLED=0` is required and
the build asserts it: a dynamic build ties the binary to the build host's glibc
and breaks on older distros.

Linux only, deliberately. The agent targets systemd hosts and drives Linux
security tooling (`ufw`, `lynis`, `rkhunter`, `maldet`), so there is no macOS or
Windows target.

Requires Go 1.26+. The version string is stamped in via
`-ldflags -X main.version=`.

## Licence

Proprietary. See [LICENSE](LICENSE). Not for redistribution.
