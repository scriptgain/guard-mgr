<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

/**
 * A single security finding produced by a scan (Run).
 *
 * Beyond the raw scan output (severity/engine/code/title/detail/remediation) a
 * finding carries a lifecycle — open -> applied|fixed|dismissed — plus the
 * remediation mapping the "fix it" layer dispatches on: {@see $fixable},
 * {@see $fix_kind}, {@see $is_risky}. The mapping is assigned at ingest by
 * {@see \App\Support\FindingClassifier}.
 */
class Finding extends Model
{
    protected $fillable = [
        'run_id', 'severity', 'engine', 'code', 'title', 'detail', 'remediation',
        'status', 'fixable', 'fix_kind', 'is_risky', 'resolved_by', 'resolved_at', 'note',
    ];

    protected function casts(): array
    {
        return [
            'fixable' => 'boolean',
            'is_risky' => 'boolean',
            'resolved_at' => 'datetime',
        ];
    }

    /** Severity ordering + weight, used when computing a hardening score. */
    public const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];

    /**
     * Lifecycle states. "open" is the default; "queued" is the interim state
     * after Apply Fix dispatches a fix_finding action but before the agent has
     * run it (so the button can't be clicked twice). Terminal states are
     * applied/fixed/dismissed.
     */
    public const STATUSES = ['open', 'queued', 'applied', 'fixed', 'dismissed'];

    /** Terminal states — a finding here needs no further action. */
    public const RESOLVED = ['applied', 'fixed', 'dismissed'];

    public function run(): BelongsTo
    {
        return $this->belongsTo(Run::class);
    }

    /** True while the finding still needs attention. */
    public function isOpen(): bool
    {
        return ($this->status ?? 'open') === 'open';
    }

    /** True once a fix has been dispatched but has not completed yet. */
    public function isQueued(): bool
    {
        return ($this->status ?? 'open') === 'queued';
    }

    /** True in a terminal state (applied/fixed/dismissed). */
    public function isResolved(): bool
    {
        return in_array($this->status ?? 'open', self::RESOLVED, true);
    }

    /**
     * Mark the finding as having a fix dispatched (interim, non-terminal). No
     * resolved_at — it isn't resolved yet, just in flight.
     */
    public function markQueued(?string $by = null, ?string $note = null): void
    {
        $this->forceFill([
            'status' => 'queued',
            'resolved_by' => $by,
            'resolved_at' => null,
            'note' => $note ?? $this->note,
        ])->save();
    }

    /** Return a queued/failed finding to the open, re-fixable state. */
    public function reopen(?string $note = null): void
    {
        $this->forceFill([
            'status' => 'open',
            'resolved_by' => null,
            'resolved_at' => null,
            'note' => $note ?? $this->note,
        ])->save();
    }

    /**
     * Resolve the finding into a terminal state, stamping who/when. `applied`
     * is set by the agent report on a successful fix; `fixed`/`dismissed` are
     * operator actions from the UI.
     */
    public function resolve(string $status, ?string $by = null, ?string $note = null): void
    {
        if (! in_array($status, self::STATUSES, true)) {
            return;
        }
        $this->forceFill([
            'status' => $status,
            'resolved_by' => $by,
            'resolved_at' => now(),
            'note' => $note ?? $this->note,
        ])->save();
    }

    /** Badge color + label for a lifecycle status. */
    public static function statusMeta(string $status): array
    {
        return [
            'open' => ['neutral', 'Open'],
            'queued' => ['warn', 'Fix Queued'],
            'applied' => ['info', 'Applied'],
            'fixed' => ['success', 'Fixed'],
            'dismissed' => ['warn', 'Dismissed'],
        ][$status] ?? ['neutral', ucfirst($status)];
    }
}
