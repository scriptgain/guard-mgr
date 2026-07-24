@php
    $statusColor = ['online' => 'success', 'offline' => 'danger', 'pending' => 'warn', 'stale' => 'warn'];
    $connLabel = ['agent' => 'Agent', 'ssh' => 'SSH', 'sftp' => 'SFTP', 'ftp' => 'FTP', 'rsync' => 'Rsync', 'multiftp' => 'Multi-FTP', 's3' => 'S3 Compatible', 'ingest' => 'Ingest'];
    $fmtBytes = function ($b) { if ($b === null) return '—'; $u=['B','KB','MB','GB','TB']; $i=0; while($b>=1000&&$i<4){$b/=1000;$i++;} return round($b,$i?1:0).' '.$u[$i]; };
@endphp
<x-layouts.app :title="$director->name">
    <x-page-header :title="$director->name" icon="cloud"
        :subtitle="collect([$director->location?->name, $director->hostname])->filter()->implode(' · ') ?: 'Director node'">
        <x-slot:actions>
            <x-button variant="secondary" icon="edit" href="{{ route('directors.edit', $director) }}">Edit</x-button>
            <x-button icon="plus" href="{{ route('hosts.create', $director) }}">Add Server</x-button>
        </x-slot:actions>
    </x-page-header>

    <div class="grid grid-cols-1 sm:grid-cols-4 gap-4 mb-6">
        <x-stat label="Location" value="{{ $director->location?->name ?? 'Unassigned' }}" icon="folder" />
        <x-stat label="Address" value="{{ $director->hostname ?: '—' }}" icon="server" />
        <x-stat label="Servers" value="{{ $director->hosts->count() }}" icon="database" />
        <x-stat label="Status" value="{{ ucfirst($director->effective_status) }}" icon="cloud" />
    </div>

    @if ($director->is_local)
        <div class="mb-6">
            <x-alert type="info" title="Local Director">
                This Director is the GuardMGR host itself. It always reads Online and needs no agent, enrollment, or authentication. It runs and queues scans for its Servers directly.
            </x-alert>
        </div>
    @endif

    <x-card title="Servers" subtitle="Servers scanned under this Director" :flush="$director->hosts->isNotEmpty()">
        @if ($director->hosts->isEmpty())
            <x-empty-state icon="server" title="No Servers Yet" description="Add a server via agent, SSH, SFTP, FTP, rsync, or S3.">
                <x-slot:action><x-button icon="plus" href="{{ route('hosts.create', $director) }}">Add Server</x-button></x-slot:action>
            </x-empty-state>
        @else
            <x-table flush>
                <thead>
                    <tr><th>Name</th><th>Connection</th><th>Address</th><th>Disks</th><th>Status</th><th class="text-right">Actions</th></tr>
                </thead>
                <tbody>
                    @foreach ($director->hosts as $h)
                        <tr>
                            <td class="font-medium text-slate-900"><a href="{{ route('hosts.show', $h) }}" class="hover:text-brand-700">{{ $h->name }}</a></td>
                            <td><x-badge color="neutral">{{ $connLabel[$h->connection_type] ?? $h->connection_type }}</x-badge></td>
                            <td class="text-slate-500 font-mono text-xs">{{ $h->ip_address ?: ($h->hostname ?: '—') }}</td>
                            <td class="tabular">{{ is_array($h->disks) ? count($h->disks) : 0 }}</td>
                            <td><x-badge :color="$statusColor[$h->effective_status] ?? 'neutral'" dot>{{ ucfirst($h->effective_status) }}</x-badge></td>
                            <td class="text-right">
                                <div class="inline-flex items-center gap-2">
                                    <x-icon-button :href="route('hosts.show', $h)" icon="eye" title="Open" />
                                    <x-icon-button :href="route('hosts.edit', $h)" icon="edit" title="Edit" />
                                    <x-delete-button :name="'del-host-' . $h->id" :action="route('hosts.destroy', $h)"
                                        title="Remove Server?" message="This removes the server, its scan jobs, and their scan history from this Director." />
                                </div>
                            </td>
                        </tr>
                    @endforeach
                </tbody>
            </x-table>
        @endif
    </x-card>

</x-layouts.app>
