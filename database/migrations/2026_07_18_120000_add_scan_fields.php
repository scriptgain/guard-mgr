<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/*
 * Phase 2 scan-engine fields.
 *
 *  - backup_jobs.engines: which security scanners a Scan Job runs
 *    (lynis|rkhunter|ufw), stored as a JSON array. Replaces the backup job's
 *    repository/retention/source config as the thing that defines the work.
 *  - hosts.latest_score / scored_at: the server's most recent hardening score,
 *    rolled up on each scan report so the Servers list + dashboard can show a
 *    per-server posture without re-querying runs.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::table('backup_jobs', function (Blueprint $table) {
            // What the agent should do for this job. 'scan' today; the seam lets
            // Phase 3-4 add apply_template / run_updates / firewall_apply /
            // quarantine without reshaping the job/poll contract.
            $table->string('action')->default('scan')->after('type');
            $table->json('engines')->nullable()->after('action');
        });

        Schema::table('hosts', function (Blueprint $table) {
            $table->unsignedTinyInteger('latest_score')->nullable()->after('agent_version');
            $table->timestamp('scored_at')->nullable()->after('latest_score');
        });
    }

    public function down(): void
    {
        Schema::table('backup_jobs', function (Blueprint $table) {
            $table->dropColumn('engines');
        });
        Schema::table('hosts', function (Blueprint $table) {
            $table->dropColumn(['latest_score', 'scored_at']);
        });
    }
};
