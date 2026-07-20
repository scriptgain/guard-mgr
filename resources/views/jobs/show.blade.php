@php
    $badge = ['success' => 'success', 'running' => 'info', 'queued' => 'neutral', 'warn' => 'warn', 'failed' => 'danger'];
    $label = ['success' => 'Passed', 'running' => 'Running', 'queued' => 'Queued', 'warn' => 'Warnings', 'failed' => 'Failed'];
    $scoreColor = function ($s) {
        if ($s === null) return 'neutral';
        if ($s >= 85) return 'success';
        if ($s >= 60) return 'warn';
        return 'danger';
    };
    $engineLabels = ['lynis' => 'Lynis', 'rkhunter' => 'rkhunter', 'ufw' => 'Firewall (ufw)'];
@endphp
<x-layouts.app :title="$job->name">
    <x-page-header :title="$job->name" icon="shield"
        :subtitle="($job->host?->name ?? '') . ' · Scan Job'">
        <x-slot:actions>
            <x-button variant="secondary" icon="edit" href="{{ route('jobs.edit', $job) }}">Edit</x-button>
            <x-confirm-action name="run-job-{{ $job->id }}" :action="route('jobs.run', $job)"
                title="Run This Scan Now?" message="Queues a scan for this job. It executes on the next agent poll." confirm="Run Now" confirmIcon="play">
                <x-button icon="play">Run Now</x-button>
            </x-confirm-action>
        </x-slot:actions>
    </x-page-header>

    <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div class="lg:col-span-2">
            @php $recentRuns = $job->runs->sortByDesc('created_at')->take(15); @endphp
            <x-card title="Recent Scans" :flush="$job->runs->isNotEmpty()">
                @if ($job->runs->isEmpty())
                    <x-empty-state icon="shield" title="No Scans Yet" description="Trigger a scan with the button above." />
                @else
                    <div
                        x-data="{
                            selected: [],
                            confirming: false,
                            allIds: [{{ $recentRuns->pluck('id')->implode(',') }}],
                            submitBulk() {
                                const f = this.$refs.bulkForm;
                                f.querySelectorAll('input.js-dyn').forEach(n => n.remove());
                                this.selected.forEach(id => {
                                    const i = document.createElement('input');
                                    i.type = 'hidden'; i.name = 'ids[]'; i.value = id; i.className = 'js-dyn';
                                    f.appendChild(i);
                                });
                                f.submit();
                            }
                        }">
                        <form method="POST" action="{{ route('runs.bulk-destroy') }}" x-ref="bulkForm" class="hidden">@csrf @method('DELETE')</form>

                        <div x-show="selected.length" x-cloak class="flex flex-wrap items-center justify-between gap-3 border-b border-slate-200 bg-brand-50 px-4 py-2.5">
                            <span class="text-sm font-medium text-brand-800"><span x-text="selected.length"></span> selected</span>
                            <div class="flex items-center gap-2">
                                <template x-if="! confirming">
                                    <x-button type="button" variant="danger" size="sm" icon="trash" x-on:click="confirming = true">Delete Selected</x-button>
                                </template>
                                <template x-if="confirming">
                                    <div class="flex flex-wrap items-center gap-2">
                                        <span class="text-sm text-brand-800">Delete <span x-text="selected.length"></span> scan(s)?</span>
                                        <x-button type="button" variant="secondary" size="sm" x-on:click="confirming = false">Cancel</x-button>
                                        <x-button type="button" variant="danger" size="sm" icon="trash" x-on:click="submitBulk()">Confirm Delete</x-button>
                                    </div>
                                </template>
                            </div>
                        </div>

                        <x-table flush>
                            <thead><tr>
                                <th class="w-10">
                                    <button type="button" role="switch"
                                        :aria-checked="(allIds.length > 0 && selected.length === allIds.length).toString()"
                                        @click="selected = (allIds.length > 0 && selected.length === allIds.length) ? [] : [...allIds]"
                                        :class="(allIds.length > 0 && selected.length === allIds.length) ? 'bg-brand-600' : 'bg-slate-300'"
                                        class="relative inline-flex h-6 w-11 shrink-0 items-center rounded-full transition-colors align-middle disabled:opacity-40"
                                        :disabled="allIds.length === 0" aria-label="Select all scans">
                                        <span :class="(allIds.length > 0 && selected.length === allIds.length) ? 'translate-x-6' : 'translate-x-1'"
                                            class="inline-block h-4 w-4 transform rounded-full bg-white shadow transition-transform"></span>
                                    </button>
                                </th>
                                <th>Status</th><th>Score</th><th>Findings</th><th>When</th><th class="text-right">Actions</th>
                            </tr></thead>
                            <tbody>
                                @foreach ($recentRuns as $r)
                                    <tr class="cursor-pointer" onclick="window.location='{{ route('runs.show', $r) }}'">
                                        <td onclick="event.stopPropagation()">
                                            <button type="button" role="switch"
                                                :aria-checked="selected.includes({{ $r->id }}).toString()"
                                                @click="selected.includes({{ $r->id }}) ? selected.splice(selected.indexOf({{ $r->id }}), 1) : selected.push({{ $r->id }}); confirming = false"
                                                :class="selected.includes({{ $r->id }}) ? 'bg-brand-600' : 'bg-slate-300'"
                                                class="relative inline-flex h-6 w-11 shrink-0 items-center rounded-full transition-colors align-middle"
                                                aria-label="Select scan">
                                                <span :class="selected.includes({{ $r->id }}) ? 'translate-x-6' : 'translate-x-1'"
                                                    class="inline-block h-4 w-4 transform rounded-full bg-white shadow transition-transform"></span>
                                            </button>
                                        </td>
                                        <td><x-badge :color="$badge[$r->status] ?? 'neutral'" dot>{{ $label[$r->status] ?? ucfirst($r->status) }}</x-badge></td>
                                        <td>@if ($r->score !== null)<x-badge :color="$scoreColor($r->score)">{{ $r->score }}/100</x-badge>@else<span class="text-slate-400 text-sm">—</span>@endif</td>
                                        <td class="tabular text-slate-600">{{ $r->findings()->count() ?: '—' }}</td>
                                        <td class="text-slate-500">{{ $r->created_at?->diffForHumans() }}</td>
                                        <td class="text-right" onclick="event.stopPropagation()">
                                            <div class="inline-flex items-center gap-2">
                                                <x-icon-button :href="route('runs.show', $r)" icon="eye" title="View Report" />
                                                <x-delete-button :name="'del-run-' . $r->id" :action="route('runs.destroy', $r)"
                                                    title="Delete Scan?" message="Removes this scan record and its findings." confirm="Delete" label="Delete Scan" />
                                            </div>
                                        </td>
                                    </tr>
                                @endforeach
                            </tbody>
                        </x-table>
                    </div>
                @endif
            </x-card>
        </div>

        <div class="space-y-6">
            <x-card title="Configuration">
                <dl class="space-y-3 text-sm">
                    <div class="flex justify-between gap-3"><dt class="text-slate-500">Server</dt><dd class="font-medium text-slate-900">{{ $job->host?->name ?? '—' }}</dd></div>
                    <div class="flex justify-between gap-3"><dt class="text-slate-500">Connector</dt><dd class="font-medium text-slate-900">{{ ucfirst($job->connector) }}</dd></div>
                    <div class="flex justify-between gap-3"><dt class="text-slate-500">Schedule</dt><dd class="font-medium text-slate-900 tabular">{{ $job->schedule_cron ?: 'Manual' }}</dd></div>
                    <div class="flex justify-between gap-3"><dt class="text-slate-500">Enabled</dt><dd><x-badge :color="$job->enabled ? 'success' : 'neutral'">{{ $job->enabled ? 'On' : 'Off' }}</x-badge></dd></div>
                    <div class="flex justify-between gap-3"><dt class="text-slate-500">Latest Score</dt><dd>@if ($job->host?->latest_score !== null)<x-badge :color="$scoreColor($job->host->latest_score)">{{ $job->host->latest_score }}/100</x-badge>@else<span class="text-slate-400">—</span>@endif</dd></div>
                </dl>
            </x-card>

            <x-card title="Scan Engines">
                <ul class="space-y-2 text-sm">
                    @foreach ($job->engineList() as $e)
                        <li class="flex items-center gap-2">
                            <span class="inline-flex h-6 w-6 items-center justify-center rounded-md bg-brand-50 text-brand-600 ring-1 ring-brand-200"><x-icon name="shield" class="h-3.5 w-3.5" /></span>
                            <span class="font-medium text-slate-800">{{ $engineLabels[$e] ?? ucfirst($e) }}</span>
                        </li>
                    @endforeach
                </ul>
            </x-card>
        </div>
    </div>
</x-layouts.app>
