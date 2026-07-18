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

        return response()->json(['job' => [
            'run_id' => (string) $run->id,
            'job_id' => (string) $job->id,
            'type' => 'scan',
            // The action discriminator the agent dispatches on. 'scan' today;
            // apply_template / run_updates / firewall_apply / quarantine are
            // reserved for later phases.
            'action' => $job->actionType(),
            'connector' => $job->connector,
            // The security scanners this job asked the agent to run.
            'engines' => $job->engineList(),
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
            'findings.*.code' => ['nullable', 'string', 'max:120'],
            'findings.*.title' => ['nullable', 'string', 'max:255'],
            'findings.*.detail' => ['nullable', 'string'],
            'findings.*.remediation' => ['nullable', 'string'],
        ]);

        $status = $data['status'];
        $final = in_array($status, ['success', 'warn', 'failed'], true);

        // On a final report, materialize the findings and derive the run status
        // from severity (any high/critical => warn) unless the agent reported a
        // hard failure. A no-op/failed scan is handled fail-soft.
        if ($final && $status !== 'failed') {
            $run->findings()->delete();
            $high = 0;
            foreach ($data['findings'] ?? [] as $f) {
                $sev = in_array($f['severity'] ?? '', Finding::SEVERITIES, true) ? $f['severity'] : 'info';
                if (in_array($sev, ['critical', 'high'], true)) {
                    $high++;
                }
                $run->findings()->create([
                    'severity' => $sev,
                    'engine' => $f['engine'] ?? null,
                    'code' => $f['code'] ?? null,
                    'title' => \Illuminate\Support\Str::limit($f['title'] ?? 'Finding', 250, ''),
                    'detail' => $f['detail'] ?? null,
                    'remediation' => $f['remediation'] ?? null,
                ]);
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
