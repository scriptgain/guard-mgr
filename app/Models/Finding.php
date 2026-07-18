<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

/**
 * A single security finding produced by a scan (Run). Phase 1 stub: the schema,
 * model, and Run relationship are in place; Phase 2's scan engines write the
 * rows and the dashboard/reporting reads them.
 */
class Finding extends Model
{
    protected $fillable = [
        'run_id', 'severity', 'engine', 'code', 'title', 'detail', 'remediation',
    ];

    /** Severity ordering + weight, used when Phase 2 computes a hardening score. */
    public const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];

    public function run(): BelongsTo
    {
        return $this->belongsTo(Run::class);
    }
}
