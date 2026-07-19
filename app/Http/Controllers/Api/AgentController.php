<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\Finding;
use App\Models\Host;
use App\Models\Run;
use App\Models\Setting;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Str;

class AgentController extends Controller
{
    /** Trade a one-time enrollment token for a permanent agent API key. */
    public function enroll(Request $request)
    {
        $data = $request->validate([
            'token' => ['required', 'string'],
            'hostname' => ['nullable', 'string'],
            'os' => ['nullable', 'string'],
            'arch' => ['nullable', 'string'],
            'agent_version' => ['nullable', 'string'],
        ]);

        $host = Host::where('enrollment_token', hash('sha256', $data['token']))->first();
        if (! $host) {
            return response()->json(['message' => 'Invalid or used enrollment token.'], 401);
        }

        $plainKey = 'vlta_' . Str::random(48);
        $host->forceFill([
            'api_key' => hash('sha256', $plainKey),
            'enrollment_token' => null,
            'status' => 'online',
            'os' => $data['os'] ?? $host->os,
            'arch' => $data['arch'] ?? $host->arch,
            'agent_version' => $data['agent_version'] ?? $host->agent_version,
            'hostname' => $host->hostname ?: ($data['hostname'] ?? null),
            'last_seen_at' => now(),
        ])->save();

        return response()->json(['host_id' => (string) $host->id, 'api_key' => $plainKey]);
    }

    /** Return the next queued run for this host, or {job:null}. */
    public function poll(Request $request)
    {
        $host = $request->attributes->get('agent_host');
        $host->forceFill(['last_seen_at' => now(), 'status' => 'online'])->save();

        // This agent runs jobs for its own host (agent connector) AND acts as the
        // gateway for agentless hosts (ftp/sftp/rsync/ssh) in the same Director.
        $run = Run::where('status', 'queued')
            ->whereHas('job', function ($q) use ($host) {
                $q->where('enabled', true)->where(function ($w) use ($host) {
                    $w->where('host_id', $host->id)
                        ->orWhereHas('host', function ($h) use ($host) {
                            $h->where('director_id', $host->director_id)
                                ->whereIn('connection_type', ['ftp', 'sftp', 'rsync', 'ssh', 'multiftp', 'ingest']);
                        });
                });
            })
            ->orderBy('id')
            ->with('job.repository', 'job.retentionPolicy', 'job.host')
            ->first();

        if (! $run) {
            return response()->json(['job' => null]);
        }

        $run->forceFill(['status' => 'running', 'started_at' => now()])->save();
        $job = $run->job;
        $s = Setting::map();

        // A Run may carry its own one-off action + params (fix_finding /
        // run_updates dispatched from the "fix it" layer); otherwise it is a
        // normal scan and the action/engines come from the carrier job.
        $params = (array) ($run->params ?? []);
        $action = $run->action ?: $job->actionType();

        return response()->json(['job' => [
            'run_id' => (string) $run->id,
            'job_id' => (string) $job->id,
            'type' => 'scan',
            // The action discriminator the agent dispatches on: scan (default),
            // fix_finding, run_updates, ...
            'action' => $action,
            'connector' => $job->connector,
            // The security scanners this job asked the agent to run. A one-off
            // run may scope its own engine list via params (e.g. updates-only).
            'engines' => ! empty($params['engines']) && is_array($params['engines'])
                ? array_values(array_intersect(array_keys(\App\Http\Controllers\JobController::ENGINES), $params['engines']))
                : $job->engineList(),
            // Remediation parameters (empty for a scan). fix_kind + target drive
            // fix_finding; update_mode (security|all) drives run_updates.
            'fix_kind' => (string) ($params['fix_kind'] ?? ''),
            'target' => (string) ($params['target'] ?? ''),
            'update_mode' => (string) ($params['update_mode'] ?? ''),
            // Optional WPScan API token — enables CVE-level WordPress vuln
            // lookups in the agent's wordpress engine. Empty falls back to
            // update-available heuristics.
            'wpscan_token' => (string) ($s['wpscan_api_token'] ?? ''),
        ]]);
    }

    /**
     * Ensure the authenticated agent is entitled to act on this run: either it
     * is the run's own host, or it is the gateway agent for an agentless host in
     * the same Director. Mirrors the claim scope in poll().
     */
    private function authorizeRunForAgent(Request $request, Run $run): void
    {
        $host = $request->attributes->get('agent_host');
        $rh = $run->loadMissing('job.host')->job?->host;
        abort_unless(
            $rh && ($rh->id === $host->id
                || ($rh->director_id === $host->director_id
                    && in_array($rh->connection_type, ['ftp', 'sftp', 'rsync', 'ssh', 'multiftp', 'ingest'], true))),
            403
        );
    }

    /**
     * Record progress or the final result of a scan run. The agent posts a
     * hardening `score` (0-100) plus a list of security `findings`; on a final
     * status we persist the score, replace the run's findings, roll the run
     * status up from finding severity, and update the server's latest score.
     */
    public function report(Request $request, Run $run)
    {
        $this->authorizeRunForAgent($request, $run);
        $data = $request->validate([
            'status' => ['required', 'in:running,success,warn,failed'],
            'score' => ['nullable', 'integer', 'between:0,100'],
            'log' => ['nullable', 'string'],
            'findings' => ['nullable', 'array'],
            'findings.*.severity' => ['nullable', 'string', 'max:20'],
            'findings.*.engine' => ['nullable', 'string', 'max:40'],
            'findings.*.code' => ['nullable', 'string', 'max:255'],
            'findings.*.title' => ['nullable', 'string', 'max:255'],
            'findings.*.detail' => ['nullable', 'string'],
            'findings.*.remediation' => ['nullable', 'string'],
            // Updates posture reported by the `updates` engine (and refreshed by a
            // run_updates action). Trusted only to populate the Server's flags.
            'updates' => ['nullable', 'array'],
            'updates.available' => ['nullable', 'integer', 'min:0'],
            'updates.security' => ['nullable', 'integer', 'min:0'],
            'updates.kernel_update' => ['nullable', 'boolean'],
            'updates.reboot_required' => ['nullable', 'boolean'],
            // Live scan progress (interim status=running reports).
            'pct' => ['nullable', 'integer', 'between:0,100'],
            'current_engine' => ['nullable', 'string', 'max:40'],
        ]);

        // Interim scan-progress ping (status=running with a percentage): persist
        // the live-progress fields without disturbing the final log/findings, and
        // throttle so a long scan doesn't hammer the DB.
        if ($data['status'] === 'running' && (! $run->action || $run->action === 'scan')
            && (array_key_exists('pct', $data) || ! empty($data['current_engine']))) {
            return $this->reportProgress($run, $data);
        }

        // A one-off remediation action (fix_finding / run_updates) reports its
        // result, not a fresh set of findings — never wipe the scan's findings.
        if ($run->action && $run->action !== 'scan') {
            return $this->reportAction($request, $run, $data);
        }

        $status = $data['status'];
        $final = in_array($status, ['success', 'warn', 'failed'], true);

        // On a final report, materialize the findings and derive the run status
        // from severity (any high/critical => warn) unless the agent reported a
        // hard failure. A no-op/failed scan is handled fail-soft.
        if ($final && $status !== 'failed') {
            // Preserve operator decisions across re-scans: a finding an operator
            // marked fixed / dismissed (or the agent applied) stays resolved when
            // the same issue is reported again on THIS host. Every scan is a new
            // Run, so we look up the most recent PREVIOUS final run for the same
            // host and carry its terminal statuses forward by signature.
            $host = $run->job?->host;
            $prior = collect();
            if ($host) {
                $prevRun = Run::where('id', '<', $run->id)
                    ->whereIn('status', ['success', 'warn'])
                    // Only prior SCAN runs carry findings; skip one-off action
                    // runs (fix_finding/run_updates) which have none and would
                    // otherwise wipe a still-valid dismissal.
                    ->where(fn ($q) => $q->whereNull('action')->orWhere('action', 'scan'))
                    ->whereHas('job', fn ($q) => $q->where('host_id', $host->id))
                    ->orderByDesc('id')
                    ->first();
                if ($prevRun) {
                    $prior = $prevRun->findings()->get()
                        ->keyBy(fn ($f) => $this->findingSignature($f->engine, $f->code, $f->title));
                }
            }

            $run->findings()->delete();
            $high = 0;
            foreach ($data['findings'] ?? [] as $f) {
                $rawSev = in_array($f['severity'] ?? '', Finding::SEVERITIES, true) ? $f['severity'] : 'info';
                $engine = $f['engine'] ?? '';
                $code = isset($f['code']) ? \Illuminate\Support\Str::limit($f['code'], 250, '') : null;
                $title = \Illuminate\Support\Str::limit($f['title'] ?? 'Finding', 250, '');

                // Map to the "fix it" layer: fix_kind + fixable/is_risky, and a
                // possibly down-ranked severity for known-benign scanner FPs.
                $cls = \App\Support\FindingClassifier::classify($engine, $code, $title, $f['detail'] ?? null, $rawSev);
                $sev = $cls['severity'];
                if (in_array($sev, ['critical', 'high'], true)) {
                    $high++;
                }

                // Carry over a terminal status from the previous run of this issue.
                $keep = $prior->get($this->findingSignature($engine, $code, $title));
                $carry = ($keep && $keep->status !== 'open') ? [
                    'status' => $keep->status,
                    'resolved_by' => $keep->resolved_by,
                    'resolved_at' => $keep->resolved_at,
                    'note' => $keep->note,
                ] : ['status' => 'open'];

                $run->findings()->create(array_merge([
                    'severity' => $sev,
                    'engine' => $engine ?: null,
                    'code' => $code,
                    'title' => $title,
                    'detail' => $f['detail'] ?? null,
                    'remediation' => $f['remediation'] ?? null,
                    'fixable' => $cls['fixable'],
                    'fix_kind' => $cls['fix_kind'],
                    'is_risky' => $cls['is_risky'],
                ], $carry));
            }
            // Any high/critical finding downgrades a "success" report to "warn".
            $status = $high > 0 ? 'warn' : $status;
        }

        $update = ['status' => $status];
        if (array_key_exists('score', $data) && $data['score'] !== null) {
            $update['score'] = $data['score'];
        }
        if (! empty($data['log'])) {
            $update['log'] = $data['log'];
        }
        if ($final) {
            $update['finished_at'] = now();
            // Complete the progress bar and stop advertising a current engine.
            $update['progress_pct'] = $status === 'failed' ? $run->progress_pct : 100;
            $update['current_engine'] = null;
        }
        if ($status === 'failed') {
            $update['error'] = $data['log'] ?? 'Scan failed.';
        }
        $run->forceFill($update)->save();

        // Roll the score up onto the scanned server so the Servers list and the
        // dashboard tile can show a per-host posture without re-querying runs.
        $host = $run->job?->host;
        if ($host) {
            if ($final && $status !== 'failed' && isset($update['score'])) {
                $host->forceFill(['latest_score' => $update['score'], 'scored_at' => now()])->save();
            }
            // The updates engine reports the host's patch posture — roll it up.
            if ($final && $status !== 'failed' && isset($data['updates'])) {
                $this->applyUpdatePosture($host, $data['updates']);
            }
            // An agent reporting in is proof it's online.
            if (in_array($status, ['running', 'success', 'warn'], true)) {
                $host->forceFill(['status' => 'online', 'last_seen_at' => now()])->save();
            }
        }

        if ($status === 'failed') {
            $this->notifyFailure($run);
        }

        return response()->noContent();
    }

    /**
     * Ingest the result of a one-off remediation run (fix_finding / run_updates).
     * On success we flip the targeted finding to "applied" and refresh the
     * Server's update posture; we never touch the scan's finding set.
     */
    private function reportAction(Request $request, Run $run, array $data): \Illuminate\Http\Response
    {
        $status = $data['status'];
        $final = in_array($status, ['success', 'warn', 'failed'], true);

        $update = ['status' => $status];
        if (! empty($data['log'])) {
            $update['log'] = $data['log'];
        }
        if ($final) {
            $update['finished_at'] = now();
        }
        if ($status === 'failed') {
            $update['error'] = $data['log'] ?? ($run->action . ' failed.');
        }
        $run->forceFill($update)->save();

        $params = (array) ($run->params ?? []);
        $host = $run->job?->host;

        // fix_finding: on success flip the targeted finding to "applied"; on
        // failure return it from "queued" to "open" so Apply Fix comes back and
        // the operator can retry. The finding is re-located by id, falling back
        // to engine+code so a re-scan that replaced the row is still handled.
        if ($final && $run->action === 'fix_finding') {
            $finding = $this->locateActionFinding($params, $host);
            if ($finding) {
                if ($status !== 'failed') {
                    $finding->resolve('applied', 'agent', \Illuminate\Support\Str::limit((string) ($data['log'] ?? ''), 1000, ''));
                } elseif (! $finding->isResolved()) {
                    $finding->reopen('Fix failed: ' . \Illuminate\Support\Str::limit((string) ($data['log'] ?? 'unknown error'), 500, ''));
                }
            }
        }

        if ($final && $status !== 'failed') {
            // Refresh the patch posture after a run_updates (reboot_required may
            // have flipped) or whenever the agent piggybacks updates info.
            if ($host && isset($data['updates'])) {
                $this->applyUpdatePosture($host, $data['updates']);
            }
        }

        if ($host && in_array($status, ['running', 'success', 'warn'], true)) {
            $host->forceFill(['status' => 'online', 'last_seen_at' => now()])->save();
        }
        if ($status === 'failed') {
            $this->notifyFailure($run);
        }

        return response()->noContent();
    }

    /**
     * Persist a live scan-progress ping: the percentage, current engine, and a
     * capped rolling log tail. Throttled — if nothing meaningful changed and the
     * row was written under 2s ago, it's a no-op so a long scan can't hammer the
     * DB. The run's final `log`/findings are never touched here.
     */
    private function reportProgress(Run $run, array $data): \Illuminate\Http\Response
    {
        $pct = array_key_exists('pct', $data) ? $data['pct'] : $run->progress_pct;
        $engine = $data['current_engine'] ?? $run->current_engine;

        $changed = $pct !== $run->progress_pct || $engine !== $run->current_engine;
        $stale = ! $run->updated_at || $run->updated_at->lt(now()->subSeconds(2));
        if ($changed || $stale) {
            $run->forceFill([
                'status' => 'running',
                'progress_pct' => $pct,
                'current_engine' => $engine,
                // Cap to the last ~64KB so a chatty scan can't bloat the row.
                'progress_log' => isset($data['log']) ? \Illuminate\Support\Str::limit((string) $data['log'], 64000, '') : $run->progress_log,
            ])->save();
        }

        // An agent streaming progress is proof it's online.
        if ($host = $run->job?->host) {
            $host->forceFill(['status' => 'online', 'last_seen_at' => now()])->save();
        }

        return response()->noContent();
    }

    /**
     * Re-locate the finding a fix_finding action targeted. Prefers the exact
     * finding_id; if a re-scan replaced that row, falls back to the newest
     * still-in-flight (queued/open) finding on the same host matching the stored
     * engine + code.
     */
    private function locateActionFinding(array $params, ?Host $host): ?Finding
    {
        if (! empty($params['finding_id'])) {
            if ($f = Finding::find($params['finding_id'])) {
                return $f;
            }
        }
        $engine = $params['engine'] ?? null;
        $code = $params['code'] ?? null;
        if (! $host || (! $engine && ! $code)) {
            return null;
        }

        return Finding::whereHas('run.job', fn ($q) => $q->where('host_id', $host->id))
            ->when($engine, fn ($q) => $q->where('engine', $engine))
            ->when($code, fn ($q) => $q->where('code', $code))
            ->whereIn('status', ['queued', 'open'])
            ->latest('id')
            ->first();
    }

    /**
     * Stable signature used to carry a finding's status across re-scans. Codes
     * are stable identifiers (e.g. a Lynis control id or chkrootkit-suspicious-
     * files), so prefer engine|code. Only when there is no code do we fall back
     * to engine|title, stripping any trailing " (N)" count so a finding whose
     * count changes (e.g. "Suspicious Hidden Files/Directories (24)" -> "(25)")
     * still matches and stays dismissed.
     */
    private function findingSignature(?string $engine, ?string $code, ?string $title): string
    {
        $eng = strtolower(trim((string) $engine));
        $code = trim((string) $code);
        if ($code !== '') {
            return $eng . '|' . strtolower($code);
        }
        $t = strtolower(trim((string) $title));
        $t = preg_replace('/\s*\(\d+\)\s*$/', '', $t);

        return $eng . '|' . $t;
    }

    /** Write the reported update counts + flags onto the Server. */
    private function applyUpdatePosture(Host $host, array $u): void
    {
        $host->forceFill([
            'updates_available' => isset($u['available']) ? (int) $u['available'] : $host->updates_available,
            'security_updates' => isset($u['security']) ? (int) $u['security'] : $host->security_updates,
            'kernel_update' => (bool) ($u['kernel_update'] ?? $host->kernel_update),
            'reboot_required' => (bool) ($u['reboot_required'] ?? $host->reboot_required),
            'updates_checked_at' => now(),
        ])->save();
    }

    /** Email the configured address when a run fails. Best effort. */
    private function notifyFailure(Run $run): void
    {
        if (Setting::get('notifications_enabled') !== '1') {
            return;
        }
        $to = Setting::get('notify_email');
        if (! $to) {
            return;
        }
        $run->loadMissing('job.host');
        $job = $run->job;
        $body = "A security scan failed.\n\n"
            . 'Scan Job: ' . ($job?->name ?? '—') . "\n"
            . 'Server: ' . ($job?->host?->name ?? '—') . "\n"
            . 'When: ' . now()->toDayDateTimeString() . "\n\n"
            . 'Error: ' . ($run->error ?: 'Unknown') . "\n";
        try {
            Mail::raw($body, function ($m) use ($to, $job) {
                $m->to($to)->subject('[' . config('brand.name') . '] Scan Failed: ' . ($job?->name ?? 'job'));
            });
        } catch (\Throwable $e) {
            // Never let a mail failure break the agent's report.
        }
    }

    public function heartbeat(Request $request)
    {
        $host = $request->attributes->get('agent_host');
        $host->forceFill([
            'last_seen_at' => now(),
            'status' => 'online',
            'agent_version' => $request->input('agent_version', $host->agent_version),
        ])->save();

        $interval = (int) (Setting::get('agent_poll_interval') ?: 0);

        return response()->json([
            'update' => $this->updateOffer(),
            'poll_interval_seconds' => $interval > 0 ? $interval : null,
            'license' => $this->licenseBlob(),
            'ingest' => $this->ingestConfigs($host),
        ]);
    }

    /**
     * Ingest (receive) connections this gateway agent should serve: every
     * ingest host in the same Director, shaped for the agent's SFTP server.
     * Only SFTP is functional today (FTP/S3 are scaffolded but not served).
     */
    private function ingestConfigs($host): array
    {
        return Host::where('director_id', $host->director_id)
            ->where('connection_type', 'ingest')
            ->get()
            ->map(fn ($h) => $h->ingestConfigForAgent())
            ->filter()
            ->values()
            ->all();
    }

    /**
     * The scriptgain-signed license (canonical payload + signature) for agents
     * to re-verify offline against the embedded vendor key. Null until the
     * install has completed at least one signed validation with scriptgain.
     */
    private function licenseBlob(): ?array
    {
        $raw = Setting::get('license_signed');
        if (! $raw) {
            return null;
        }
        $blob = json_decode($raw, true);

        return (is_array($blob) && isset($blob['canonical'], $blob['signature'])) ? $blob : null;
    }

    /** Advertise a newer agent build when auto-update is enabled and configured. */
    private function updateOffer(): ?array
    {
        $s = Setting::map();
        if (($s['agent_auto_update'] ?? '0') !== '1') {
            return null;
        }
        $version = trim($s['agent_latest_version'] ?? '');
        $url = trim($s['agent_download_url'] ?? '');
        $sha256 = strtolower(trim($s['agent_download_sha256'] ?? ''));
        $signature = trim($s['agent_download_signature'] ?? '');
        // The agent refuses any offer without a checksum + vendor signature (and a
        // non-https URL), so advertising a half-configured update just wastes a
        // download. Withhold the offer until all four fields are set.
        if ($version === '' || $url === '' || $sha256 === '' || $signature === '') {
            return null;
        }

        return [
            'version' => $version,
            'url' => $url,
            'sha256' => $sha256,
            'signature' => $signature,
        ];
    }
}
