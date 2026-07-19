<?php

namespace Database\Seeders;

use App\Models\BackupJob;
use App\Models\Director;
use App\Models\Finding;
use App\Models\Host;
use App\Models\Location;
use App\Models\Run;
use App\Models\ScheduleTemplate;
use App\Models\Setting;
use App\Models\User;
use Illuminate\Database\Seeder;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;

/**
 * Read-only public demo data for GuardMGR: a fleet of scanned hosts with
 * hardening scores, ~30 days of scan history, and current security findings.
 * Idempotent. Never run on a real install.
 *
 *   php artisan db:seed --class=DemoSeeder
 */
class DemoSeeder extends Seeder
{
    /** engine, severity, code, title, detail, remediation, fixable, fix_kind */
    private array $pool = [
        ['lynis', 'high', 'SSH-7412', 'Root login over SSH is permitted', 'PermitRootLogin is set to yes in sshd_config, allowing direct root access.', 'Set PermitRootLogin to no and restart sshd.', true, 'config'],
        ['lynis', 'medium', 'AUTH-9286', 'No password aging configured', 'User accounts have no maximum password age set.', 'Set PASS_MAX_DAYS in /etc/login.defs.', true, 'config'],
        ['lynis', 'high', 'FIRE-4512', 'Host firewall is not enabled', 'No active ufw or nftables ruleset was found on the host.', 'Enable ufw and allow only required ports.', true, 'command'],
        ['lynis', 'low', 'KRNL-5820', 'Core dumps are not restricted', 'Core dumps can leak sensitive memory to disk.', 'Set a hard limit on core dumps in limits.conf.', false, null],
        ['lynis', 'medium', 'BOOT-5122', 'No password set on the bootloader', 'GRUB has no password, allowing single-user boot tampering.', 'Set a GRUB password.', false, null],
        ['rkhunter', 'medium', 'RKH-0021', 'Suspicious file in /tmp', 'A world-writable executable was found in /tmp.', 'Review and remove the file if it is unexpected.', false, null],
        ['rkhunter', 'low', 'RKH-0044', 'Hidden directory found', 'A hidden directory exists under /dev; can be legitimate.', 'Investigate the directory contents.', false, null],
        ['fail2ban', 'medium', 'F2B-0001', 'No active fail2ban jails', 'fail2ban is installed but no jails are enabled.', 'Enable the sshd jail at minimum.', true, 'config'],
        ['updates', 'medium', 'UPD-0100', 'Security updates pending', 'Package updates include security fixes that are not yet applied.', 'Run the OS update job during a maintenance window.', true, 'command'],
        ['updates', 'low', 'UPD-0200', 'Reboot required', 'A kernel update requires a reboot to take effect.', 'Schedule a reboot.', false, null],
        ['wordpress', 'high', 'WP-0301', 'Outdated WordPress plugin', 'contact-form-7 is several versions behind and has a known CVE.', 'Update the plugin to the latest version.', true, 'command'],
        ['wordpress', 'high', 'WP-0302', 'WordPress core out of date', 'The WordPress core is not on the latest release.', 'Update WordPress core.', true, 'command'],
        ['clamav', 'critical', 'CLAM-1001', 'Malware signature match', 'The EICAR test signature was detected in an uploads folder.', 'Quarantine and remove the file, then investigate the vector.', true, 'quarantine'],
        ['chkrootkit', 'critical', 'CHK-2001', 'Possible rootkit indicator', 'chkrootkit flagged a suspicious loadable kernel module.', 'Investigate immediately and isolate the host.', false, null],
    ];

    public function run(): void
    {
        DB::statement('SET FOREIGN_KEY_CHECKS=0');
        foreach (['findings', 'runs', 'backup_jobs', 'hosts', 'schedule_templates', 'directors', 'locations'] as $t) {
            DB::table($t)->truncate();
        }
        DB::statement('SET FOREIGN_KEY_CHECKS=1');

        $admin = User::updateOrCreate(['email' => 'demo@scriptgain.com'],
            ['name' => 'Demo Admin', 'password' => Hash::make(Str::random(40)), 'role' => 'admin', 'email_verified_at' => now()]);
        User::updateOrCreate(['email' => 'analyst@scriptgain.com'],
            ['name' => 'Jordan Kim', 'password' => Hash::make(Str::random(40)), 'role' => 'operator', 'email_verified_at' => now()]);
        $uid = $admin->id;
        Setting::updateOrCreate(['key' => 'setup_complete'], ['value' => '1']);

        foreach ([
            ['Daily at 2 AM', '0 2 * * *', 'Once a day, overnight.'],
            ['Every 6 Hours', '0 */6 * * *', 'Four scans a day.'],
            ['Weekly (Sunday 3 AM)', '0 3 * * 0', 'Once a week, early Sunday.'],
        ] as [$tn, $cron, $td]) {
            ScheduleTemplate::create(['name' => $tn, 'slug' => Str::slug($tn), 'cron' => $cron, 'description' => $td, 'is_system' => true]);
        }

        $sites = [
            ['US East', 'Ashburn, Virginia', 'us-east-1', 'director-use1', true],
            ['US West', 'San Jose, California', 'us-west-1', 'director-usw1', false],
            ['EU Central', 'Frankfurt, Germany', 'eu-central-1', 'director-euc1', false],
            ['APAC', 'Singapore', 'ap-southeast-1', 'director-apse1', false],
        ];
        $directors = [];
        foreach ($sites as [$name, $addr, $region, $dname, $isLocal]) {
            $loc = Location::create(['name' => $name, 'slug' => Str::slug($name), 'address' => $addr, 'region' => $region]);
            $directors[] = Director::create([
                'location_id' => $loc->id, 'user_id' => $uid, 'name' => $dname, 'slug' => Str::slug($dname),
                'region' => $region, 'is_local' => $isLocal, 'status' => 'online',
                'api_key' => 'dk_'.Str::random(32), 'version' => '0.4.4', 'last_seen_at' => now()->subSeconds(random_int(5, 90)),
            ]);
        }

        $hostDefs = [
            ['web-prod-01', 'ubuntu 22.04'], ['db-primary', 'debian 12'], ['app-node-2', 'ubuntu 22.04'],
            ['mail-gw', 'rocky 9'], ['file-server', 'ubuntu 20.04'], ['k8s-worker-3', 'almalinux 9'],
            ['wordpress-01', 'ubuntu 22.04'], ['redis-cache', 'debian 12'], ['analytics-01', 'ubuntu 22.04'],
            ['legacy-crm', 'centos 7'], ['edge-proxy', 'ubuntu 22.04'], ['staging-01', 'debian 12'],
        ];

        $totalRuns = 0; $totalFindings = 0;
        foreach ($hostDefs as $j => [$hn, $os]) {
            $d = $directors[$j % count($directors)];
            $roll = random_int(1, 100);
            $st = $roll <= 62 ? 'online' : ($roll <= 95 ? 'offline' : 'pending');
            $online = $st === 'online';
            $secUpdates = random_int(0, 30);

            $host = Host::create([
                'director_id' => $d->id, 'user_id' => $uid, 'name' => $hn, 'connection_type' => 'agent',
                'hostname' => $hn.'.'.$d->slug.'.internal',
                'disks' => ['/', '/var', '/home'],
                'os' => $os, 'arch' => 'x86_64', 'agent_version' => '0.4.4',
                'status' => $st,
                'last_seen_at' => $st === 'pending' ? null : ($online ? now()->subSeconds(random_int(5, 120)) : now()->subHours(random_int(6, 40))),
                'updates_available' => $secUpdates + random_int(0, 40), 'security_updates' => $secUpdates,
                'kernel_update' => (bool) random_int(0, 1), 'reboot_required' => (bool) random_int(0, 1),
                'updates_checked_at' => now()->subHours(random_int(1, 20)),
            ]);

            if ($st === 'pending') {
                continue; // enrolled, not yet scanned
            }

            $job = BackupJob::create([
                'host_id' => $host->id, 'name' => $hn.' security scan', 'type' => 'scan', 'action' => 'scan',
                'engines' => 'lynis,rkhunter,chkrootkit,clamav,fail2ban,updates', 'connector' => 'agent',
                'schedule_cron' => '0 2 * * *', 'enabled' => true, 'ad_hoc' => false, 'prune_after_backup' => false,
            ]);

            // ~30 days of nightly scans, score trending; findings on the latest scan.
            $days = random_int(20, 30);
            $latestScore = random_int(38, 96);
            $latestRun = null;
            for ($n = $days; $n >= 0; $n--) {
                $start = now()->subDays($n)->setTime(2, random_int(0, 59), random_int(0, 59));
                $status = ($online && $n < 3 && random_int(1, 100) <= 10) ? 'failed' : 'success';
                // earlier scans score a little lower (improving posture over time)
                $score = $status === 'failed' ? null : max(20, min(100, $latestScore - $n * random_int(0, 1) - random_int(0, 4)));
                $run = Run::create([
                    'backup_job_id' => $job->id, 'status' => $status, 'action' => 'scan', 'score' => $score,
                    'started_at' => $start, 'finished_at' => $status === 'failed' ? $start->copy()->addMinutes(1) : $start->copy()->addMinutes(random_int(2, 9)),
                    'current_engine' => null, 'progress_pct' => 100,
                    'log' => $status === 'failed' ? "starting scan\nagent unreachable" : "starting scan\nlynis... rkhunter... chkrootkit... clamav...\nscan complete, score {$score}",
                    'error' => $status === 'failed' ? 'agent heartbeat lost during scan' : null,
                    'created_at' => $start, 'updated_at' => $start,
                ]);
                $totalRuns++;
                if ($status === 'success') {
                    $latestRun = $run; $latestScore = $score;
                }
            }

            // Current findings on the latest successful scan; more + worse for lower scores.
            if ($latestRun) {
                $count = $latestScore >= 85 ? random_int(0, 2) : ($latestScore >= 60 ? random_int(2, 5) : random_int(4, 8));
                $picks = collect($this->pool)
                    ->filter(fn ($f) => $latestScore >= 70 ? ! in_array($f[1], ['critical'], true) : true) // criticals only on weak hosts
                    ->shuffle()->take($count);
                foreach ($picks as [$engine, $sev, $code, $title, $detail, $rem, $fixable, $kind]) {
                    Finding::create([
                        'run_id' => $latestRun->id, 'severity' => $sev, 'engine' => $engine, 'code' => $code,
                        'title' => $title, 'detail' => $detail, 'remediation' => $rem,
                        'status' => 'open', 'fixable' => $fixable, 'fix_kind' => $kind,
                    ]);
                    $totalFindings++;
                }
                $host->forceFill(['latest_score' => $latestScore, 'scored_at' => $latestRun->finished_at])->save();
            }
        }

        $this->command?->info("Guard demo seeded: ".count($hostDefs)." hosts, {$totalRuns} scans, {$totalFindings} findings.");
    }
}
