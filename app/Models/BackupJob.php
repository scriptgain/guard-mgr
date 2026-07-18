<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;

class BackupJob extends Model
{
    use \App\Models\Concerns\Auditable;
    protected $table = 'backup_jobs';

    protected $fillable = [
        'host_id', 'repository_id', 'retention_policy_id', 'name', 'type',
        'action', 'engines', 'connector', 'source', 'schedule_cron', 'enabled', 'ad_hoc',
        'prune_after_backup', 'prune_schedule_cron', 'pre_hook', 'post_hook',
    ];

    protected function casts(): array
    {
        return [
            'source' => 'array',
            'engines' => 'array',
            'enabled' => 'boolean',
            'ad_hoc' => 'boolean',
            'prune_after_backup' => 'boolean',
        ];
    }

    /** What the agent should do for this job; 'scan' is the only live action. */
    public function actionType(): string
    {
        return $this->action ?: 'scan';
    }

    /** Scanners this job runs, always a clean list (defaults to Lynis). */
    public function engineList(): array
    {
        $allowed = ['lynis', 'rkhunter', 'ufw'];
        $engines = array_values(array_intersect($allowed, (array) ($this->engines ?? [])));

        return $engines ?: ['lynis'];
    }

    public function host(): BelongsTo
    {
        return $this->belongsTo(Host::class);
    }

    public function repository(): BelongsTo
    {
        return $this->belongsTo(Repository::class);
    }

    public function retentionPolicy(): BelongsTo
    {
        return $this->belongsTo(RetentionPolicy::class);
    }

    public function runs(): HasMany
    {
        return $this->hasMany(Run::class);
    }
}
