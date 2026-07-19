<?php

namespace App\Http\Controllers;

use App\Models\AuditLog;
use App\Models\Finding;
use App\Models\Host;
use App\Models\Run;
use Illuminate\Http\Request;
use Illuminate\Validation\Rule;

/**
 * The "fix it" layer. Turns findings into actions:
 *   - Apply Fix    — dispatch a fix_finding action to the Server's agent.
 *   - Mark Fixed   — operator handled it manually (status=fixed).
 *   - Dismiss / FP — false positive or accepted risk (status=dismissed),
 *                    optionally adding rkhunter findings to the baseline.
 *   - Update Now   — dispatch a run_updates action (security-only or all).
 *
 * Fix dispatch only works for enrolled agent Servers; the agent runs the
 * remediation locally, backs up any file it edits, and reports the result — on
 * success the finding flips to "applied" in the agent report handler.
 */
class RemediationController extends Controller
{
    /** A finding is visible when its Server is visible to the current user. */
    private function guardFinding(Finding $finding): Host
    {
        $host = $finding->loadMissing('run.job.host.director')->run?->job?->host;
        abort_unless($host && $host->isVisibleTo(auth()->user()), 403);

        return $host;
    }

    /** Ensure the Server can actually run an agent-side remediation. */
    private function assertAgentReady(Host $host): void
    {
        abort_unless($host->canRemediate(), 422);
    }

    /** Apply Fix — queue a fix_finding action for the finding's remediation. */
    public function apply(Finding $finding)
    {
        $host = $this->guardFinding($finding);
        if (! $finding->fixable || ! $finding->fix_kind) {
            return back()->with('warning', 'This finding has no automatic fix. Use Mark as Fixed or Dismiss instead.');
        }
        // Duplicate guard: a fix already in flight (or a resolved finding) must
        // not dispatch a second run.
        if ($finding->isQueued()) {
            return back()->with('warning', 'A fix for this finding is already queued.');
        }
        if ($finding->isResolved()) {
            return back()->with('warning', 'This finding is already resolved.');
        }
        $this->assertAgentReady($host);

        $this->dispatchFix($host, $finding);
        AuditLog::record('remediate', "Apply Fix queued ({$finding->fix_kind}) for finding \"{$finding->title}\"", $finding);

        return back()->with('status', 'Fix queued. The agent applies it (with a backup) on its next poll, then the finding flips to Applied.');
    }

    /**
     * Queue a fix_finding action for a finding and mark it "queued" so the Apply
     * Fix button can't be clicked again until the run completes (or fails back to
     * open). engine + code are carried so the report can re-locate the finding
     * even if a re-scan replaced the row in the meantime.
     */
    private function dispatchFix(Host $host, Finding $finding): void
    {
        $host->queueAction('fix_finding', [
            'fix_kind' => $finding->fix_kind,
            'target' => (string) $finding->code,
            'finding_id' => $finding->id,
            'engine' => $finding->engine,
            'code' => $finding->code,
        ]);
        $finding->markQueued(auth()->user()->name, "Fix dispatched: {$finding->fix_kind}");
    }

    /** Mark as Fixed — operator resolved it manually. */
    public function markFixed(Finding $finding)
    {
        $this->guardFinding($finding);
        $finding->resolve('fixed', auth()->user()->name);
        AuditLog::record('remediate', "Marked fixed: finding \"{$finding->title}\"", $finding);

        return back()->with('status', 'Finding marked as fixed.');
    }

    /** Dismiss / False Positive — optionally baseline rkhunter FPs. */
    public function dismiss(Request $request, Finding $finding)
    {
        $host = $this->guardFinding($finding);
        $note = $request->string('note')->limit(1000, '')->value() ?: null;
        $finding->resolve('dismissed', auth()->user()->name, $note);

        // "Add to baseline" for an rkhunter false positive: run --propupd so the
        // warning stops recurring on the next scan.
        $baselined = false;
        if ($request->boolean('add_to_baseline') && $finding->engine === 'rkhunter' && $host->canRemediate()) {
            $host->queueAction('fix_finding', ['fix_kind' => 'rkhunter-propupd', 'finding_id' => $finding->id]);
            $baselined = true;
        }
        AuditLog::record('remediate', "Dismissed finding \"{$finding->title}\"" . ($baselined ? ' (+ baselined)' : ''), $finding);

        return back()->with('status', 'Finding dismissed' . ($baselined ? '; rkhunter baseline update queued.' : '.'));
    }

    /** Reopen a resolved finding. */
    public function reopen(Finding $finding)
    {
        $this->guardFinding($finding);
        $finding->forceFill(['status' => 'open', 'resolved_by' => null, 'resolved_at' => null])->save();

        return back()->with('status', 'Finding reopened.');
    }

    /** Bulk apply / mark-fixed / dismiss on selected findings within a run. */
    public function bulk(Request $request, Run $run)
    {
        $run->loadMissing('job.host.director');
        abort_unless($run->job?->host?->isVisibleTo(auth()->user()), 403);

        $data = $request->validate([
            'op' => ['required', Rule::in(['apply', 'mark-fixed', 'dismiss'])],
            'ids' => ['required', 'array', 'min:1'],
            'ids.*' => ['integer'],
        ]);

        $host = $run->job->host;
        $findings = $run->findings()->whereIn('id', $data['ids'])->get();
        if ($findings->isEmpty()) {
            return back()->with('warning', 'No matching findings were selected.');
        }

        $n = 0;
        foreach ($findings as $f) {
            switch ($data['op']) {
                case 'apply':
                    // Skip anything already in flight or resolved — no duplicates.
                    if ($f->fixable && $f->fix_kind && $host->canRemediate() && $f->isOpen()) {
                        $this->dispatchFix($host, $f);
                        $n++;
                    }
                    break;
                case 'mark-fixed':
                    $f->resolve('fixed', auth()->user()->name);
                    $n++;
                    break;
                case 'dismiss':
                    $f->resolve('dismissed', auth()->user()->name);
                    $n++;
                    break;
            }
        }
        AuditLog::record('remediate', "Bulk {$data['op']} on {$n} finding(s) in scan #{$run->id}", $run);

        $verb = ['apply' => 'Fix queued for', 'mark-fixed' => 'Marked fixed', 'dismiss' => 'Dismissed'][$data['op']];

        return back()->with('status', "{$verb} {$n} finding" . ($n === 1 ? '' : 's') . '.');
    }

    /** Update Now — dispatch a run_updates action for a Server. */
    public function runUpdates(Request $request, Host $host)
    {
        abort_unless($host->isVisibleTo(auth()->user()), 403);
        $this->assertAgentReady($host);
        $mode = $request->input('mode') === 'all' ? 'all' : 'security';

        $host->queueAction('run_updates', ['update_mode' => $mode]);
        AuditLog::record('remediate', "Update Now ({$mode}) queued for {$host->name}", $host);

        $label = $mode === 'all' ? 'all available updates' : 'security updates';

        return back()->with('status', "Update queued ({$label}). The agent applies it on its next poll and reports whether a reboot is required.");
    }

    /** Queue a lightweight updates-only scan to refresh the Server's posture. */
    public function checkUpdates(Host $host)
    {
        abort_unless($host->isVisibleTo(auth()->user()), 403);
        $this->assertAgentReady($host);

        // A normal scan, but scoped to just the updates engine via run params.
        $host->queueAction('scan', ['engines' => ['updates']]);

        return back()->with('status', 'Update check queued. Posture refreshes on the next agent poll.');
    }
}
