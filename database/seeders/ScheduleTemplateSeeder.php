<?php

namespace Database\Seeders;

use App\Models\ScheduleTemplate;
use Illuminate\Database\Seeder;

/**
 * Built-in schedule-template presets so the Schedule Templates page ships
 * populated. Idempotent (updateOrCreate by slug) — safe to re-run, and wired
 * into a migration so fresh installs get them too. Marked is_system so they read
 * as built-in presets.
 */
class ScheduleTemplateSeeder extends Seeder
{
    public const TEMPLATES = [
        ['name' => 'Daily Full Scan', 'slug' => 'daily-full-scan', 'cron' => '0 3 * * *',
            'description' => 'Runs every scan engine overnight at 3 AM.'],
        ['name' => 'Weekly Deep Scan', 'slug' => 'weekly-deep-scan', 'cron' => '0 2 * * 0',
            'description' => 'Full weekly audit including ClamAV and maldet malware scans (Sundays, 2 AM).'],
        ['name' => 'Every 6 Hours — Rootkit & Firewall', 'slug' => 'rootkit-firewall-6h', 'cron' => '0 */6 * * *',
            'description' => 'Quick posture check: rkhunter, chkrootkit, firewall, and fail2ban.'],
        ['name' => 'Malware Watch — Every 4 Hours', 'slug' => 'malware-watch-4h', 'cron' => '0 */4 * * *',
            'description' => 'Lightweight recurring malware watch (ClamAV + maldet).'],
    ];

    public function run(): void
    {
        foreach (self::TEMPLATES as $t) {
            ScheduleTemplate::updateOrCreate(
                ['slug' => $t['slug']],
                ['name' => $t['name'], 'cron' => $t['cron'], 'description' => $t['description'], 'is_system' => true],
            );
        }
    }
}
