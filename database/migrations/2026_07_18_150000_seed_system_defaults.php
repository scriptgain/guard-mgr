<?php

use App\Http\Controllers\JobController;
use App\Models\BackupJob;
use App\Models\Host;
use Database\Seeders\ScheduleTemplateSeeder;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\Schema;

/*
 * Seed built-in defaults so the product is useful out of the box:
 *   - the system schedule-template presets (idempotent, via the seeder), and
 *   - a default daily "Full Scan" Job for the local Server (server001) on the
 *     Daily Full Scan cadence, so guard:dispatch-due queues an unattended scan
 *     every night without anyone wiring one by hand.
 *
 * Both are guarded/idempotent so re-running or fresh installs stay clean.
 */
return new class extends Migration
{
    public function up(): void
    {
        if (Schema::hasTable('schedule_templates')) {
            (new ScheduleTemplateSeeder)->run();
        }

        // Default recurring scan for the local Server, if present and not already
        // wired. Uses the Daily Full Scan cadence (03:00) with every engine.
        if (! Schema::hasTable('hosts') || ! Schema::hasTable('backup_jobs')) {
            return;
        }
        $host = Host::where('is_local', true)->orWhere('id', 1)->first();
        if (! $host) {
            return;
        }
        $exists = BackupJob::where('host_id', $host->id)
            ->where('ad_hoc', false)
            ->whereNotNull('schedule_cron')
            ->exists();
        if ($exists) {
            return;
        }

        BackupJob::create([
            'host_id' => $host->id,
            'name' => 'Daily Full Scan',
            'type' => 'scan',
            'engines' => array_keys(JobController::ENGINES),
            'connector' => $host->connection_type ?: 'agent',
            'schedule_cron' => '0 3 * * *',
            'enabled' => true,
            'ad_hoc' => false,
        ]);
    }

    public function down(): void
    {
        // Leave seeded defaults in place on rollback (non-destructive).
    }
};
