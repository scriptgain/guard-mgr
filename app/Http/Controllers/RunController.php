<?php

namespace App\Http\Controllers;

use App\Models\AuditLog;
use App\Models\Run;
use Illuminate\Http\Request;

class RunController extends Controller
{
    /** Scan History — recent scans across all servers the user can see. */
    public function index()
    {
        $user = auth()->user();

        $runs = Run::whereHas('job.host.director', fn ($q) => $q->visibleTo($user))
            ->with('job:id,name,host_id', 'job.host:id,name')
            ->latest()
            ->paginate(25);

        return view('runs.index', compact('runs'));
    }

    public function show(Run $run)
    {
        $run->load('job.host.director', 'findings');
        $this->guard($run);

        return view('runs.show', compact('run'));
    }

    private function guard(Run $run): void
    {
        abort_unless(
            auth()->user()->isAdmin() || $run->job?->host?->director?->user_id === auth()->id(),
            403
        );
    }

    public function destroy(Run $run)
    {
        $run->loadMissing('job.host.director');
        $this->guard($run);
        $job = $run->job;
        $run->delete();

        return redirect()
            ->route('jobs.show', $job)
            ->with('status', 'Run deleted.');
    }

    /**
     * Bulk-delete selected run records. Only operates on the ids explicitly
     * submitted, and only on runs the current user is allowed to access.
     */
    public function bulkDestroy(Request $request)
    {
        $data = $request->validate([
            'ids' => ['required', 'array', 'min:1'],
            'ids.*' => ['integer'],
        ]);

        $user = auth()->user();
        $runs = Run::with('job.host.director')->whereIn('id', $data['ids'])->get()
            ->filter(fn (Run $run) => $user->isAdmin() || $run->job?->host?->director?->user_id === $user->id);

        if ($runs->isEmpty()) {
            return back()->with('warning', 'No matching runs were selected.');
        }

        $count = $runs->count();
        Run::whereIn('id', $runs->pluck('id')->all())->delete();

        AuditLog::record('run', "Bulk deleted {$count} run".($count === 1 ? '' : 's').'.');

        return back()->with('status', $count.' run'.($count === 1 ? '' : 's').' deleted.');
    }
}
