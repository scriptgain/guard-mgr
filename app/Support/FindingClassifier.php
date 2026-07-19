<?php

namespace App\Support;

/**
 * Maps a raw scan finding to the "fix it" layer: a remediation slug the agent
 * knows how to run ({@see fix_kind}), whether it is {@see fixable} / {@see
 * is_risky}, and a possibly down-ranked severity so known-benign scanner false
 * positives don't drown the real signal.
 *
 * Everything here is a pure function of the finding's engine/code/title/detail,
 * so the same mapping applies whether a finding is ingested fresh or replayed.
 * The agent's remediate package must implement every fix_kind emitted here.
 */
class FindingClassifier
{
    /**
     * Packages Lynis routinely suggests installing. When a suggestion clearly
     * names one, we can install it safely via `install-pkg:<name>`.
     */
    private const INSTALLABLE = [
        'libpam-tmpdir', 'debsums', 'apt-listbugs', 'apt-listchanges',
        'needrestart', 'fail2ban', 'acct', 'sysstat', 'aide', 'rkhunter',
    ];

    /**
     * rkhunter warning fragments that are near-always false positives on a
     * managed host (CloudPanel dotfiles, post-update property drift, signature
     * heuristics). These get down-ranked and offered "add to baseline".
     */
    private const RKHUNTER_BENIGN = [
        'ifpromisc', 'promiscuous', 'rh-sharpe', 'sharpe', 'universal rootkit',
        ' urk ', 'bpfdoor', 'xzibit', 'suckit', 'has changed', 'have changed',
        'file properties', 'hidden file', 'hidden directory',
        '/etc/.fstab', '/etc/.updated', '/etc/.clp_', '/dev/.blkid', '/dev/.udev',
        '/dev/.initramfs', '/dev/.static',
    ];

    /**
     * Classify a finding. Returns:
     *   ['fix_kind' => ?string, 'fixable' => bool, 'is_risky' => bool, 'severity' => string]
     * severity is the (possibly adjusted) severity to store.
     */
    public static function classify(string $engine, ?string $code, ?string $title, ?string $detail, string $severity): array
    {
        $engine = strtolower($engine);
        $code = strtoupper(trim((string) $code));
        $hay = strtolower(trim(($title ?? '') . ' ' . ($detail ?? '')));

        $out = ['fix_kind' => null, 'fixable' => false, 'is_risky' => false, 'severity' => $severity];

        // ---- updates engine -------------------------------------------------
        if ($engine === 'updates') {
            return match (true) {
                str_contains(strtolower($code), 'updates-available')
                    => ['fix_kind' => 'apt-upgrade', 'fixable' => true, 'is_risky' => false, 'severity' => $severity],
                str_contains(strtolower($code), 'kernel-update')
                    => ['fix_kind' => 'apt-upgrade', 'fixable' => true, 'is_risky' => false, 'severity' => $severity],
                // A pending reboot can't be auto-applied safely — surface as a flag
                // and let the operator Mark Fixed after rebooting.
                str_contains(strtolower($code), 'reboot-required')
                    => ['fix_kind' => null, 'fixable' => false, 'is_risky' => true, 'severity' => $severity],
                default => $out,
            };
        }

        // ---- rkhunter -------------------------------------------------------
        if ($engine === 'rkhunter') {
            foreach (self::RKHUNTER_BENIGN as $needle) {
                if (str_contains(' ' . $hay . ' ', $needle)) {
                    // Down-rank the FP and offer a one-click baseline update.
                    $sev = in_array($severity, ['critical', 'high'], true)
                        ? (str_contains($hay, 'properties') || str_contains($hay, 'changed') ? 'low' : 'info')
                        : $severity;

                    return ['fix_kind' => 'rkhunter-propupd', 'fixable' => true, 'is_risky' => false, 'severity' => $sev];
                }
            }

            // Real rkhunter warnings stay as-is; not auto-fixable, but the UI
            // still lets an operator dismiss + baseline them as false positives.
            return $out;
        }

        // ---- lynis ----------------------------------------------------------
        if ($engine === 'lynis') {
            // SSH hardening — risky (changes sshd_config). Carry the option in the
            // fix_kind so the agent tweaks exactly that directive.
            if (str_starts_with($code, 'SSH-7408')) {
                $opt = self::sshOption($hay);

                return ['fix_kind' => 'ssh-harden:' . $opt, 'fixable' => $opt !== '', 'is_risky' => true, 'severity' => $severity];
            }
            // Kernel sysctl tuning — risky (changes kernel parameters).
            if (str_starts_with($code, 'KRNL-6000')) {
                return ['fix_kind' => 'sysctl', 'fixable' => true, 'is_risky' => true, 'severity' => $severity];
            }
            // Vulnerable / outdated packages — safe apt upgrade.
            if (str_starts_with($code, 'PKGS-7392') || str_contains($hay, 'security update') || str_contains($hay, 'vulnerable package')) {
                return ['fix_kind' => 'apt-upgrade', 'fixable' => true, 'is_risky' => false, 'severity' => $severity];
            }
            // Postfix banner leaks the mail server version — safe postconf edit.
            if (str_starts_with($code, 'MAIL-8818') || (str_contains($hay, 'banner') && str_contains($hay, 'postfix'))) {
                return ['fix_kind' => 'postfix-banner', 'fixable' => true, 'is_risky' => false, 'severity' => $severity];
            }
        }

        // ---- cross-engine keyword mappings ---------------------------------
        // Postfix VRFY command enabled — safe postconf edit.
        if (str_contains($hay, 'vrfy')) {
            return ['fix_kind' => 'disable-vrfy', 'fixable' => true, 'is_risky' => false, 'severity' => $severity];
        }
        // Redis without a password — generate + set requirepass.
        if (str_contains($hay, 'redis') && (str_contains($hay, 'requirepass') || str_contains($hay, 'password') || str_contains($hay, 'no auth') || str_contains($hay, 'unauthenticated'))) {
            return ['fix_kind' => 'redis-requirepass', 'fixable' => true, 'is_risky' => false, 'severity' => $severity];
        }
        // A package Lynis suggests installing.
        if ($engine === 'lynis' && (str_contains($hay, 'install') || str_starts_with($code, 'PKGS-7370'))) {
            foreach (self::INSTALLABLE as $pkg) {
                if (str_contains($hay, $pkg)) {
                    return ['fix_kind' => 'install-pkg:' . $pkg, 'fixable' => true, 'is_risky' => false, 'severity' => $severity];
                }
            }
        }

        return $out;
    }

    /**
     * Pull the sshd_config directive out of an SSH-7408 suggestion. Lynis phrases
     * these as "... - <Directive> (set YES to NO)". Returns '' when none matches
     * our safe, known set (so we don't offer to change something we can't map).
     */
    private static function sshOption(string $hay): string
    {
        $known = [
            'allowtcpforwarding' => 'AllowTcpForwarding',
            'clientalivecountmax' => 'ClientAliveCountMax',
            'maxauthtries' => 'MaxAuthTries',
            'maxsessions' => 'MaxSessions',
            'permitrootlogin' => 'PermitRootLogin',
            'tcpkeepalive' => 'TCPKeepAlive',
            'x11forwarding' => 'X11Forwarding',
            'logingracetime' => 'LoginGraceTime',
            'permituserenvironment' => 'PermitUserEnvironment',
            'compression' => 'Compression',
            'allowagentforwarding' => 'AllowAgentForwarding',
        ];
        foreach ($known as $needle => $directive) {
            if (str_contains(str_replace(' ', '', $hay), $needle)) {
                return $directive;
            }
        }

        return '';
    }
}
