<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;

/**
 * A Run is one execution of a scan job — the "Scan" in the GuardMGR UI. It keeps
 * the same lifecycle as its BackupMGR ancestor (queued -> running ->
 * success/warn/failed), but its result is a hardening `score` plus a set of
 * {@see Finding} rows rather than a backup snapshot. The legacy bytes_/files/
 * snapshot columns are retained (dormant) so the agent's report shape stays
 * backward-compatible until Phase 2 repurposes them.
 */
class Run extends Model
{
    protected $fillable = [
        'backup_job_id', 'status', 'score', 'started_at', 'finished_at',
        'bytes_in', 'bytes_uploaded', 'files', 'snapshot_id', 'log', 'error', 'file_index',
    ];

    protected function casts(): array
    {
        return [
            'started_at' => 'datetime',
            'finished_at' => 'datetime',
            'file_index' => 'array',
        ];
    }

    public function job(): BelongsTo
    {
        return $this->belongsTo(BackupJob::class, 'backup_job_id');
    }

    /** Findings produced by this scan (Phase 2 populates these). */
    public function findings(): HasMany
    {
        return $this->hasMany(Finding::class);
    }
}
