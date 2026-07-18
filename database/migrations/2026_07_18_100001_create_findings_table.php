<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/*
 * Findings — the per-scan result rows. Each Run (Scan) produces zero or more
 * findings; the scan's hardening score is derived from their severities.
 *
 * Phase 1 ships the schema + model + relationship only. Phase 2 populates rows
 * from the agent's scan engines (Lynis controls, rkhunter warnings, ufw state).
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create('findings', function (Blueprint $table) {
            $table->id();
            $table->foreignId('run_id')->constrained('runs')->cascadeOnDelete();
            // critical|high|medium|low|info — drives the score + severity chip.
            $table->string('severity')->default('info');
            // Which scan engine produced it (lynis|rkhunter|ufw|...). Free-form
            // so Phase 2 can add engines without a migration.
            $table->string('engine')->nullable();
            // Stable identifier from the engine (e.g. a Lynis control id), for
            // dedupe + linking to remediation guidance later.
            $table->string('code')->nullable();
            $table->string('title');
            $table->text('detail')->nullable();
            // Suggested remediation, when the engine offers one.
            $table->text('remediation')->nullable();
            $table->timestamps();

            $table->index(['run_id', 'severity']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('findings');
    }
};
