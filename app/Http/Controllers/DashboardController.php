<?php

namespace App\Http\Controllers;

use App\Models\BackupJob;
use App\Models\Director;
use App\Models\Host;
use App\Models\Run;

class DashboardController extends Controller
{
    public function __invoke()
    {
        $user = auth()->user();
        $visible = fn ($q) => $q->visibleTo($user);

        $stats = [
            'directors' => Director::visibleTo($user)->count(),
            'hosts' => Host::whereHas('director', $visible)->count(),
            'jobs' => BackupJob::where('enabled', true)->whereHas('host.director', $visible)->count(),
            'scans' => Run::whereHas('job.host.director', $visible)->count(),
        ];

        // Fleet health.
        $failed24h = Run::where('status', 'failed')->where('created_at', '>=', now()->subDay())
            ->whereHas('job.host.director', $visible)->count();

        $staleHosts = Host::where('connection_type', 'agent')
            ->whereHas('director', $visible)
            ->whereNotNull('api_key')
            ->where(fn ($q) => $q->whereNull('last_seen_at')->orWhere('last_seen_at', '<', now()->subMinutes(10)))
            ->count();

        // Hardening score — fleet average of each server's latest score, plus the
        // per-server breakdown the tile lists. Null until the first scan reports.
        $scoredHosts = Host::whereHas('director', $visible)
            ->whereNotNull('latest_score')
            ->orderBy('latest_score')
            ->get(['id', 'name', 'latest_score', 'scored_at']);
        $hardeningScore = $scoredHosts->isNotEmpty() ? (int) round($scoredHosts->avg('latest_score')) : null;
        $serverScores = $scoredHosts->take(6);

        // Patch posture — Servers with pending updates or a required reboot.
        $updateHosts = Host::whereHas('director', $visible)
            ->where(fn ($q) => $q->where('reboot_required', true)
                ->orWhere('kernel_update', true)
                ->orWhere('updates_available', '>', 0))
            ->orderByDesc('reboot_required')->orderByDesc('kernel_update')->orderByDesc('security_updates')
            ->get(['id', 'name', 'updates_available', 'security_updates', 'kernel_update', 'reboot_required']);
        $rebootCount = $updateHosts->where('reboot_required', true)->count();

        $attention = Run::whereIn('status', ['failed', 'warn'])
            ->whereHas('job.host.director', $visible)
            ->with('job:id,name,host_id', 'job.host:id,name')
            ->latest()->limit(5)->get();

        $runs = Run::whereHas('job.host.director', $visible)
            ->with('job:id,name,host_id', 'job.host:id,name')
            ->latest()->limit(8)->get();

        // 14-day scan activity for the dashboard sparkline. Pulled in one query
        // and bucketed per day in PHP so it stays portable across SQLite/MySQL.
        $since = now()->subDays(13)->startOfDay();
        $recent = Run::whereHas('job.host.director', $visible)
            ->where('created_at', '>=', $since)
            ->get(['created_at', 'status']);

        $activity = collect(range(0, 13))->map(function ($i) use ($recent) {
            $day = now()->subDays(13 - $i)->startOfDay();
            $next = $day->copy()->addDay();
            $onDay = $recent->filter(fn ($r) => $r->created_at >= $day && $r->created_at < $next);

            return [
                'label' => $day->format('M j'),
                'total' => $onDay->count(),
                'success' => $onDay->where('status', 'success')->count(),
                'issues' => $onDay->whereIn('status', ['failed', 'warn'])->count(),
            ];
        })->all();

        $windowTotal = (int) array_sum(array_column($activity, 'total'));
        $windowSuccess = (int) array_sum(array_column($activity, 'success'));
        $successRate = $windowTotal ? (int) round($windowSuccess / $windowTotal * 100) : null;

        return view('dashboard', compact(
            'stats', 'runs', 'failed24h', 'staleHosts', 'hardeningScore', 'attention',
            'activity', 'windowTotal', 'successRate', 'serverScores',
            'updateHosts', 'rebootCount',
        ));
    }
}
