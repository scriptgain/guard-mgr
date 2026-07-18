<x-layouts.app title="Scan Jobs">
    <x-page-header title="Scan Jobs" icon="clock" subtitle="Which servers get scanned, by which engines, on what schedule.">
        <x-slot:actions>
            <x-button icon="plus" href="{{ route('jobs.create') }}">New Scan Job</x-button>
        </x-slot:actions>
    </x-page-header>

    @if ($jobs->isEmpty())
        <x-card>
            <x-empty-state icon="clock" title="No Scan Jobs Yet" description="Create a scan job for a server and choose which engines to run.">
                <x-slot:action><x-button icon="plus" href="{{ route('jobs.create') }}">New Scan Job</x-button></x-slot:action>
            </x-empty-state>
        </x-card>
    @else
        <x-table>
            <thead>
                <tr><th>Name</th><th>Server</th><th>Engines</th><th>Schedule</th><th>Enabled</th><th class="text-right">Actions</th></tr>
            </thead>
            <tbody>
                @foreach ($jobs as $j)
                    <tr>
                        <td class="font-medium text-slate-900"><a href="{{ route('jobs.show', $j) }}" class="hover:text-brand-700">{{ $j->name }}</a></td>
                        <td>{{ $j->host?->name ?? '—' }}</td>
                        <td>
                            <div class="flex flex-wrap gap-1">
                                @foreach ($j->engineList() as $e)
                                    <x-badge color="neutral">{{ $e === 'ufw' ? 'ufw' : ucfirst($e) }}</x-badge>
                                @endforeach
                            </div>
                        </td>
                        <td class="tabular text-slate-500">{{ $j->schedule_cron ?: 'Manual' }}</td>
                        <td><x-badge :color="$j->enabled ? 'success' : 'neutral'">{{ $j->enabled ? 'On' : 'Off' }}</x-badge></td>
                        <td class="text-right">
                            <div class="inline-flex items-center gap-2">
                                <x-confirm-action name="run-{{ $j->id }}" :action="route('jobs.run', $j)"
                                    title="Run This Scan Now?" message="Queues a scan for this job. It executes on the next agent poll." confirm="Run Now" confirmIcon="play">
                                    <x-icon-button type="button" icon="play" title="Run Now" variant="brand" />
                                </x-confirm-action>
                                <x-icon-button :href="route('jobs.show', $j)" icon="eye" title="Open" />
                                <x-icon-button :href="route('jobs.edit', $j)" icon="edit" title="Edit" />
                                <x-delete-button :name="'del-job-' . $j->id" :action="route('jobs.destroy', $j)"
                                    title="Delete Scan Job?" message="This deletes the scan job, its schedule, and its scan history." />
                            </div>
                        </td>
                    </tr>
                @endforeach
            </tbody>
        </x-table>
    @endif
</x-layouts.app>
