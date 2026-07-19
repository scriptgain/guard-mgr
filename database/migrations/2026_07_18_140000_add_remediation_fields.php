<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/*
 * Remediation wave — the "fix it" layer.
 *
 * Adds the finding lifecycle (status + who/when resolved), the remediation
 * mapping (fixable / fix_kind / is_risky) the agent dispatches on, the per-Server
 * update posture the `updates` engine reports, and a one-off action carrier on
 * runs so a Run can dispatch a `fix_finding` / `run_updates` action independent
 * of its (ad-hoc) carrier job. All additive.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::table('findings', function (Blueprint $table) {
            // open (default) | applied (agent ran a fix) | fixed (operator handled
            // it) | dismissed (false positive / accepted risk).
            $table->string('status')->default('open')->index();
            // True when the agent has a remediation for this finding's fix_kind.
            $table->boolean('fixable')->default(false);
            // Slug the agent maps to a remediation (apt-upgrade, install-pkg:<pkg>,
            // postfix-banner, disable-vrfy, redis-requirepass, ssh-harden:<opt>,
            // sysctl:<key>, rkhunter-propupd). Null when no known fix.
            $table->string('fix_kind')->nullable();
            // Risky fixes change system config (SSH/sysctl/firewall) and get a
            // confirm modal + backup/revert note before Apply Fix dispatches.
            $table->boolean('is_risky')->default(false);
            // Who/when the finding left "open", and an optional operator note.
            $table->string('resolved_by')->nullable();
            $table->timestamp('resolved_at')->nullable();
            $table->text('note')->nullable();
        });

        Schema::table('hosts', function (Blueprint $table) {
            // The local Server IS the GuardMGR host itself — always trusted +
            // online, no agent enrollment/auth required (mirrors Director::is_local).
            $table->boolean('is_local')->default(false);
            // Latest posture from the updates engine, surfaced on the Server page
            // and dashboard without re-querying runs/findings.
            $table->unsignedInteger('updates_available')->nullable();
            $table->unsignedInteger('security_updates')->nullable();
            $table->boolean('kernel_update')->default(false);
            $table->boolean('reboot_required')->default(false);
            $table->timestamp('updates_checked_at')->nullable();
        });

        // The GuardMGR host runs as host id 1 (server001). Mark it local so it
        // needs no enrollment. Guarded: only if a matching host is present.
        if (Schema::hasTable('hosts')) {
            \Illuminate\Support\Facades\DB::table('hosts')->where('id', 1)->update(['is_local' => true]);
        }

        Schema::table('runs', function (Blueprint $table) {
            // A one-off remediation action (fix_finding | run_updates | ...). Null
            // means "derive the action from the carrier job" (a normal scan).
            $table->string('action')->nullable();
            // Action parameters: fix_kind, target, finding_id, update_mode, etc.
            $table->json('params')->nullable();
        });
    }

    public function down(): void
    {
        Schema::table('findings', function (Blueprint $table) {
            $table->dropColumn(['status', 'fixable', 'fix_kind', 'is_risky', 'resolved_by', 'resolved_at', 'note']);
        });
        Schema::table('hosts', function (Blueprint $table) {
            $table->dropColumn(['is_local', 'updates_available', 'security_updates', 'kernel_update', 'reboot_required', 'updates_checked_at']);
        });
        Schema::table('runs', function (Blueprint $table) {
            $table->dropColumn(['action', 'params']);
        });
    }
};
