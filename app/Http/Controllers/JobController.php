<?php

namespace App\Http\Controllers;

use App\Models\BackupJob;
use App\Models\Host;
use App\Models\Run;
use Illuminate\Http\Request;
use Illuminate\Validation\Rule;

/**
 * Scan Jobs. A job pins a server + a set of security engines (Lynis, rkhunter,
 * ufw) + a schedule; the dispatcher queues a Run for it, an agent picks the Run
 * up on poll, runs the scanners, and reports a hardening score + findings.
 *
 * (The model/table are still named "backup_job" from the BackupMGR lineage; the
 * product surface is entirely scan-oriented.)
 */
class JobController extends Controller
{
    /** The security scanners a job may run, with a human label + one-liner. */
    public const ENGINES = [
        'lynis' => ['Lynis', 'System hardening audit — computes the hardening index and flags weak controls.'],
        'rkhunter' => ['rkhunter', 'Rootkit, backdoor, and local exploit scanner.'],
        'ufw' => ['Firewall (ufw)', 'Checks the host firewall is active and reports exposed ports.'],
    ];

    public function index()
    {
        $jobs = BackupJob::where('ad_hoc', false)
            ->whereHas('host', fn ($q) => $q->visibleTo(auth()->user()))
            ->with('host.director')->latest()->get();

        return view('jobs.index', compact('jobs'));
    }

    private function guard(BackupJob $job): void
    {
        abort_unless($job->host?->isVisibleTo(auth()->user()), 403);
    }

    public function create(Request $request)
    {
        $user = auth()->user();
        $hosts = Host::visibleTo($user)->with('director:id,name')->orderBy('name')->get();
        $scheduleTemplates = \App\Models\ScheduleTemplate::orderBy('name')->get();
        $selectedHost = $request->integer('host');
        $engines = self::ENGINES;

        return view('jobs.create', compact('hosts', 'scheduleTemplates', 'selectedHost', 'engines'));
    }

    /** Validation shared by store + update. */
    private function rules(): array
    {
        return [
            'host_id' => ['required', Rule::exists('hosts', 'id')],
            'name' => ['required', 'string', 'max:120'],
            'engines' => ['required', 'array', 'min:1'],
            'engines.*' => [Rule::in(array_keys(self::ENGINES))],
            'schedule_cron' => ['nullable', 'string', 'max:120'],
            'enabled' => ['boolean'],
        ];
    }

    public function store(Request $request)
    {
        $data = $request->validate($this->rules());

        $host = Host::findOrFail($data['host_id']);
        abort_unless($host->isVisibleTo(auth()->user()), 403);

        $job = BackupJob::create([
            'host_id' => $host->id,
            'name' => $data['name'],
            'type' => 'scan',
            'engines' => array_values($data['engines']),
            'connector' => $host->connection_type,
            'schedule_cron' => ($data['schedule_cron'] ?? null) ?: null,
            'enabled' => $request->boolean('enabled'),
        ]);

        return redirect()->route('jobs.show', $job)->with('status', "Scan Job \"{$job->name}\" created.");
    }

    public function show(BackupJob $job)
    {
        $job->load('host.director', 'runs');
        $this->guard($job);

        return view('jobs.show', compact('job'));
    }

    public function edit(BackupJob $job)
    {
        $job->load('host.director');
        $this->guard($job);
        $user = auth()->user();
        $hosts = Host::visibleTo($user)->with('director:id,name')->orderBy('name')->get();
        $scheduleTemplates = \App\Models\ScheduleTemplate::orderBy('name')->get();
        $engines = self::ENGINES;

        return view('jobs.edit', compact('job', 'hosts', 'scheduleTemplates', 'engines'));
    }

    public function update(Request $request, BackupJob $job)
    {
        $job->loadMissing('host.director');
        $this->guard($job);
        $data = $request->validate($this->rules());

        $host = Host::findOrFail($data['host_id']);
        abort_unless($host->isVisibleTo(auth()->user()), 403);

        $job->update([
            'host_id' => $host->id,
            'name' => $data['name'],
            'type' => 'scan',
            'engines' => array_values($data['engines']),
            'connector' => $host->connection_type,
            'schedule_cron' => ($data['schedule_cron'] ?? null) ?: null,
            'enabled' => $request->boolean('enabled'),
        ]);

        return redirect()->route('jobs.show', $job)->with('status', "Scan Job \"{$job->name}\" updated.");
    }

    public function destroy(BackupJob $job)
    {
        $job->loadMissing('host.director');
        $this->guard($job);
        $name = $job->name;
        $job->delete();

        return redirect()->route('jobs.index')->with('status', "Scan Job \"{$name}\" deleted.");
    }

    /** Queue a scan now; the agent picks it up on its next poll. */
    public function run(BackupJob $job)
    {
        $job->loadMissing('host.director');
        $this->guard($job);
        Run::create(['backup_job_id' => $job->id, 'status' => 'queued']);
        \App\Models\AuditLog::record('scan', 'Scan queued for job "'.$job->name.'"', $job);

        return redirect()->route('jobs.show', $job)->with('status', 'Scan queued. It will run on the next agent poll.');
    }
}
