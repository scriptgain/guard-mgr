<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * In-place rename for installs upgrading from the BackupMGR-era schema:
 * backup_jobs -> scan_jobs and runs.backup_job_id -> runs.scan_job_id.
 *
 * Guarded so it is a no-op on fresh installs (where the create-migrations
 * already make scan_jobs / scan_job_id) and safe to run once on old ones.
 */
return new class extends Migration
{
    public function up(): void
    {
        if (Schema::hasTable('backup_jobs') && ! Schema::hasTable('scan_jobs')) {
            Schema::rename('backup_jobs', 'scan_jobs');
        }

        if (Schema::hasColumn('runs', 'backup_job_id') && ! Schema::hasColumn('runs', 'scan_job_id')) {
            Schema::table('runs', function (Blueprint $table) {
                $table->renameColumn('backup_job_id', 'scan_job_id');
            });
        }
    }

    public function down(): void
    {
        // One-way: the product no longer has a backup_jobs concept.
    }
};
