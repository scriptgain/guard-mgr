@php
    $statusColor = ['online' => 'success', 'offline' => 'danger', 'pending' => 'warn', 'stale' => 'warn'];
@endphp
<x-layouts.app :title="$host->name">
    <x-page-header :title="$host->name" icon="server"
        :subtitle="'Director: ' . $host->director->name">
        <x-slot:actions>
            <x-badge :color="$statusColor[$host->effective_status] ?? 'neutral'" dot>{{ ucfirst($host->effective_status) }}</x-badge>
            <x-button variant="secondary" icon="edit" href="{{ route('hosts.edit', $host) }}">Edit</x-button>
            <x-confirm-action name="scan-host-{{ $host->id }}" :action="route('hosts.scan', $host)"
                title="Run Scan Now?" message="This queues a scan for every enabled scan job on this Server. The agent picks it up on its next poll." confirm="Run Scan Now" confirmIcon="play">
                <x-button icon="play">Run Scan Now</x-button>
            </x-confirm-action>
            <x-delete-button :name="'del-host-' . $host->id" :action="route('hosts.destroy', $host)"
                title="Remove Server?" message="This removes the Server, its scan jobs, and their scan history." />
        </x-slot:actions>
    </x-page-header>

    <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div class="lg:col-span-2 space-y-6">



            <x-card title="Scan Jobs" :flush="$host->jobs->isNotEmpty()">
                <x-slot:actions>
                    <x-button size="sm" icon="plus" href="{{ route('jobs.index') }}">New Job</x-button>
                </x-slot:actions>
                @if ($host->jobs->isEmpty())
                    <x-empty-state icon="clock" title="No Jobs Yet" description="Create a scan job to audit this Server on a schedule." />
                @else
                    <x-table flush>
                        <thead><tr><th>Name</th><th>Type</th><th>Schedule</th><th>Enabled</th></tr></thead>
                        <tbody>
                            @foreach ($host->jobs as $j)
                                <tr>
                                    <td class="font-medium text-slate-900">{{ $j->name }}</td>
                                    <td>{{ ucfirst($j->type) }}</td>
                                    <td class="tabular">{{ $j->schedule_cron ?? 'Manual' }}</td>
                                    <td><x-badge :color="$j->enabled ? 'success' : 'neutral'">{{ $j->enabled ? 'On' : 'Off' }}</x-badge></td>
                                </tr>
                            @endforeach
                        </tbody>
                    </x-table>
                @endif
            </x-card>
        </div>

        <div class="space-y-6">
            {{-- OS Updates posture + Update Now (agent / local Servers). --}}
            @if ($host->canRemediate())
                @php
                    $upd = $host->updates_available;
                    $sec = $host->security_updates;
                    $updColor = $host->reboot_required ? '#f43f5e' : (($sec ?? 0) > 0 ? '#f59e0b' : (($upd ?? 0) > 0 ? '#3b82f6' : '#10b981'));
                @endphp
                <x-card title="OS Updates" subtitle="Package, kernel & reboot posture">
                    <x-slot:actions>
                        <form method="POST" action="{{ route('hosts.check-updates', $host) }}">@csrf
                            <x-button type="submit" size="sm" variant="secondary" icon="refresh">Check</x-button>
                        </form>
                    </x-slot:actions>
                    @if ($host->updates_checked_at)
                        <div class="grid grid-cols-2 gap-4 text-sm">
                            <div><dt class="text-slate-500">Available</dt><dd class="mt-0.5 text-lg font-semibold tabular text-slate-900">{{ $upd ?? '—' }}</dd></div>
                            <div><dt class="text-slate-500">Security</dt><dd class="mt-0.5 text-lg font-semibold tabular" style="color:{{ ($sec ?? 0) > 0 ? '#f59e0b' : '#10b981' }}">{{ $sec ?? '—' }}</dd></div>
                        </div>
                        <div class="mt-3 flex flex-wrap gap-2">
                            @if ($host->kernel_update)
                                <span class="inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-medium ring-1 ring-inset" style="color:#f43f5e;background-color:#f43f5e12;border-color:#f43f5e30"><span class="h-1.5 w-1.5 rounded-full bg-rose-500"></span> Kernel Update</span>
                            @endif
                            @if ($host->reboot_required)
                                <span class="inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-medium ring-1 ring-inset" style="color:#f43f5e;background-color:#f43f5e12;border-color:#f43f5e30"><span class="h-1.5 w-1.5 rounded-full bg-rose-500"></span> Reboot Required</span>
                            @endif
                            @if (! $host->kernel_update && ! $host->reboot_required && ($upd ?? 0) === 0)
                                <span class="inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-medium ring-1 ring-inset" style="color:#10b981;background-color:#10b98112;border-color:#10b98130"><span class="h-1.5 w-1.5 rounded-full bg-emerald-500"></span> Up To Date</span>
                            @endif
                        </div>
                        <p class="mt-3 text-xs text-slate-400">Checked {{ $host->updates_checked_at->diffForHumans() }}.</p>
                    @else
                        <p class="text-sm text-slate-500">No update scan yet. Run a scan with the OS Updates engine, or click Check to refresh the posture on the next agent poll.</p>
                    @endif

                    <div class="mt-4 flex flex-col gap-2">
                        <x-confirm-action :name="'upd-sec-' . $host->id" :action="route('hosts.update-now', $host)"
                            title="Apply Security Updates?" message="This installs pending security updates on the Server and reports whether a reboot is then required. It does not run a full upgrade."
                            confirm="Apply Security Updates" confirmIcon="download">
                            <x-button type="button" size="sm" icon="download" class="w-full">Update Now (Security)</x-button>
                        </x-confirm-action>
                        <x-confirm-action :name="'upd-all-' . $host->id" :action="route('hosts.update-now', [$host, 'mode' => 'all'])"
                            title="Apply ALL Updates?" message="This runs a full package upgrade on the Server (apt-get upgrade), which can be disruptive. It reports whether a reboot is required afterward. Proceed only during a maintenance window."
                            confirm="Apply All Updates" confirmIcon="download" confirmVariant="danger" tone="danger">
                            <x-button type="button" size="sm" variant="secondary" icon="download" class="w-full">Update Now (All)</x-button>
                        </x-confirm-action>
                    </div>
                </x-card>
            @endif

            @if ($host->is_local)
                <x-card title="Local Server">
                    <p class="text-sm text-slate-600">This Server is the GuardMGR host itself. It always reads Online and needs no agent enrollment or authentication. Scans and fixes run on it directly.</p>
                    <p class="mt-3 text-xs text-emerald-600 flex items-center gap-1.5"><x-icon name="check-circle" class="w-4 h-4" /> Local — no enrollment needed.</p>
                </x-card>
            @elseif ($host->connection_type === 'agent')
                <x-card title="Agent Enrollment">
                    @if (session('enroll_token'))
                        <p class="text-sm text-slate-600">Run this on the host as root (copy now — shown once):</p>
                        <pre class="mt-2 rounded-lg bg-chrome text-slate-100 text-xs p-3 overflow-x-auto"><code>curl -fsSL {{ config('app.url') }}/downloads/agent-install.sh \
  | sudo bash -s -- {{ config('app.url') }} {{ session('enroll_token') }}</code></pre>
                        <p class="mt-2 text-xs text-slate-500">One command: downloads the agent, enrolls this host, and installs an always-on systemd service that polls every ~30s and runs due scans automatically. The agent only dials out — no inbound ports.</p>
                    @else
                        <p class="text-sm text-slate-500">Generate a one-time token, then run the install one-liner on the host. It enrolls and starts an always-on service in a single step — the agent dials out only, no inbound ports.</p>
                    @endif
                    @if ($host->api_key)
                        <p class="mt-4 text-xs text-emerald-600 flex items-center gap-1.5"><x-icon name="check-circle" class="w-4 h-4" /> Agent enrolled.</p>
                        <x-confirm-action
                            :name="'rotate-key-' . $host->id"
                            :action="route('hosts.enroll', $host)"
                            title="Rotate Agent Key?"
                            message="This revokes the current agent key immediately. The running agent stops working until you re-run the install command with the new token. Proceed?"
                            confirm="Rotate Key" confirmVariant="danger" confirmIcon="key" tone="danger">
                            <x-button type="button" icon="key" variant="secondary" size="sm" class="mt-3 w-full">Rotate Agent Key</x-button>
                        </x-confirm-action>
                    @else
                        <form method="POST" action="{{ route('hosts.enroll', $host) }}" class="mt-4">
                            @csrf
                            <x-button type="submit" icon="key" variant="secondary" size="sm" class="w-full">Generate Enrollment Token</x-button>
                        </form>
                    @endif
                </x-card>
            @endif

        </div>
    </div>
</x-layouts.app>
