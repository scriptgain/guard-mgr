<?php

namespace App\Http\Controllers;

use App\Models\Director;
use App\Models\Host;
use App\Models\Run;
use Illuminate\Http\Request;
use Illuminate\Support\Str;
use Illuminate\Validation\Rule;

class HostController extends Controller
{
    public function index()
    {
        $user = auth()->user();
        $hosts = Host::visibleTo($user)
            ->with('director:id,name', 'owner:id,name')->latest()->get();
        $directors = Director::visibleTo($user)->orderBy('name')->get();

        return view('hosts.index', compact('hosts', 'directors'));
    }

    private function guardDirector(Director $director): void
    {
        abort_unless(auth()->user()->isAdmin() || $director->user_id === auth()->id(), 403);
    }

    private function guard(Host $host): void
    {
        abort_unless($host->isVisibleTo(auth()->user()), 403);
    }

    /** Users an admin may assign as a host owner. Non-admins get an empty list. */
    private function assignableOwners()
    {
        return auth()->user()->isAdmin()
            ? \App\Models\User::orderBy('name')->get(['id', 'name', 'email'])
            : collect();
    }

    public function create(Director $director)
    {
        $this->guardDirector($director);
        $scheduleTemplates = \App\Models\ScheduleTemplate::orderBy('name')->get();
        $owners = $this->assignableOwners();

        return view('hosts.create', compact('director', 'scheduleTemplates', 'owners'));
    }

    /**
     * Validation rules shared by store() and update(). GuardMGR hosts are always
     * agent hosts: you install the agent, it scans locally. There is no remote
     * connector, so no connection/credential fields.
     */
    private function hostRules(): array
    {
        return [
            'name' => ['required', 'string', 'max:120'],
            'default_schedule_template_id' => ['nullable', Rule::exists('schedule_templates', 'id')],
            'owner_id' => ['nullable', Rule::exists('users', 'id')],
            'notes' => ['nullable', 'string'],
        ];
    }

    public function store(Request $request, Director $director)
    {
        $this->guardDirector($director);
        $data = $request->validate($this->hostRules());

        // Only admins may assign a host to another user; otherwise it inherits
        // the director's owner (user_id stays null).
        $data['user_id'] = auth()->user()->isAdmin() ? ($data['owner_id'] ?? null) : null;
        unset($data['owner_id']);
        $data['connection_type'] = 'agent';
        $data['status'] = 'pending';

        $host = $director->hosts()->create($data);

        return redirect()
            ->route('hosts.show', $host)
            ->with('status', "Server \"{$host->name}\" added. Install the agent on it (see the enrollment command), then create a scan job.");
    }

    public function show(Host $host)
    {
        $this->guard($host);
        $host->load(['director:id,name', 'jobs' => fn ($q) => $q->where('ad_hoc', false)]);

        return view('hosts.show', compact('host'));
    }

    public function edit(Host $host)
    {
        $this->guard($host);
        $scheduleTemplates = \App\Models\ScheduleTemplate::orderBy('name')->get();
        $owners = $this->assignableOwners();

        return view('hosts.edit', compact('host', 'scheduleTemplates', 'owners'));
    }

    public function update(Request $request, Host $host)
    {
        $this->guard($host);
        $data = $request->validate($this->hostRules());
        // Only admins may reassign ownership; non-admins can't change it.
        if (auth()->user()->isAdmin()) {
            $data['user_id'] = $data['owner_id'] ?? null;
        }
        unset($data['owner_id']);
        $host->update($data);

        return redirect()->route('hosts.show', $host)->with('status', "Host \"{$host->name}\" updated.");
    }

    /** Queue a run for every enabled (non-ad-hoc) scan job on this host. */
    public function scan(Host $host)
    {
        $this->guard($host);
        $jobs = $host->jobs()->where('enabled', true)->where('ad_hoc', false)->get();
        if ($jobs->isEmpty()) {
            return back()->with('status', 'This host has no enabled scan jobs yet. Create a scan job first.');
        }
        $queued = 0;
        foreach ($jobs as $job) {
            $busy = Run::where('scan_job_id', $job->id)->whereIn('status', ['queued', 'running'])->exists();
            if (! $busy) {
                Run::create(['scan_job_id' => $job->id, 'status' => 'queued']);
                $queued++;
            }
        }

        return back()->with('status', "Scan queued for {$queued} job(s) on {$host->name}. Runs on the next agent poll.");
    }

    /**
     * Generate a one-time enrollment token for the agent (shown once). If the
     * host is already enrolled, this rotates the credential: the current agent
     * API key is revoked immediately, so a leaked key stops working and the host
     * must re-enroll with the new token.
     */
    public function enroll(Host $host)
    {
        $this->guard($host);

        $rotating = (bool) $host->api_key;
        $plain = 'vlte_' . Str::random(40);
        $host->forceFill([
            'enrollment_token' => hash('sha256', $plain),
            'api_key' => null,   // revoke the existing agent credential
            'status' => 'pending',
        ])->save();

        \App\Models\AuditLog::record(
            $rotating ? 'key_rotate' : 'enroll',
            ($rotating ? 'Rotated agent key for host "' : 'Issued enrollment token for host "') . $host->name . '"',
            $host
        );

        return back()
            ->with('enroll_token', $plain)
            ->with('status', $rotating
                ? 'Key rotated. The old agent key is now revoked — re-run the install command below to reconnect.'
                : 'Enrollment token generated. Copy it now — it is shown only once.');
    }

    public function destroy(Host $host)
    {
        $this->guard($host);
        $director = $host->director;
        $name = $host->name;
        $host->delete();

        return redirect()
            ->route('directors.show', $director)
            ->with('status', "Host \"{$name}\" removed.");
    }
}
