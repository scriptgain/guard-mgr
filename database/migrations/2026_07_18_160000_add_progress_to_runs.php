<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/*
 * Live scan progress. While a scan runs, the agent POSTs interim status=running
 * reports carrying a percentage, the current engine, and a rolling log tail so
 * the report page can show live progress instead of a bare "running". These are
 * distinct from the run's final `log` (set once, on completion).
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::table('runs', function (Blueprint $table) {
            $table->unsignedTinyInteger('progress_pct')->nullable();
            $table->string('current_engine')->nullable();
            $table->text('progress_log')->nullable();
        });
    }

    public function down(): void
    {
        Schema::table('runs', function (Blueprint $table) {
            $table->dropColumn(['progress_pct', 'current_engine', 'progress_log']);
        });
    }
};
