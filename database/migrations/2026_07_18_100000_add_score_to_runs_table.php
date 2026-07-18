<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/*
 * Scan seam (Phase 1 stub). A "Scan" reuses the Run lifecycle
 * (queued -> running -> success/warn/failed) but its result is a hardening
 * score + a set of findings instead of a backup snapshot. Phase 2 (the Go
 * agent running Lynis/rkhunter/ufw) fills these in.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::table('runs', function (Blueprint $table) {
            // 0-100 hardening score computed from the scan's findings. Null until
            // the scan engine reports one.
            $table->unsignedTinyInteger('score')->nullable()->after('status');
        });
    }

    public function down(): void
    {
        Schema::table('runs', function (Blueprint $table) {
            $table->dropColumn('score');
        });
    }
};
