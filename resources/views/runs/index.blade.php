@php
    // Scan status -> chip color + label.
    $badge = ['success' => 'success', 'running' => 'info', 'queued' => 'neutral', 'warn' => 'warn', 'failed' => 'danger'];
    $label = ['success' => 'Passed', 'running' => 'Running', 'queued' => 'Queued', 'warn' => 'Warnings', 'failed' => 'Failed'];

    // Hardening score -> chip color. Null until a scan reports one.
    $scoreColor = function ($s) {
        if ($s === null) return 'neutral';
        if ($s >= 85) return 'success';
        if ($s >= 60) return 'warn';
        return 'danger';
    };
@endphp

<x-layouts.app title="Scan History">
    <x-page-header title="Scan History" subtitle="Recent security scans across your fleet." icon="shield" />

    <x-card :flush="$runs->isNotEmpty()">
        @if ($runs->isEmpty())
            <x-empty-state icon="shield" title="No Scans Yet"
                description="Add a Server and a Scan Job, then run it to see hardening results here.">
                <x-slot:action><x-button icon="plus" href="{{ route('jobs.create') }}">New Scan Job</x-button></x-slot:action>
            </x-empty-state>
        @else
            <div x-data="{
                    selected: [],
                    confirming: false,
                    allIds: [{{ $runs->pluck('id')->implode(',') }}],
                    get allOn() { return this.allIds.length && this.selected.length === this.allIds.length; },
                    toggleAll() { this.allOn ? this.selected = [] : this.selected = [...this.allIds]; },
                    submitBulk() {
                        const f = this.$refs.bulkForm;
                        f.querySelectorAll('input.js-dyn').forEach(n => n.remove());
                        this.selected.forEach(id => { const i = document.createElement('input'); i.type = 'hidden'; i.name = 'ids[]'; i.value = id; i.className = 'js-dyn'; f.appendChild(i); });
                        (f.requestSubmit ? f.requestSubmit() : f.submit());
                    }
                }">
                <form method="POST" action="{{ route('runs.bulk-destroy') }}" x-ref="bulkForm" class="hidden">@csrf @method('DELETE')</form>

                {{-- Bulk action bar --}}
                <div x-show="selected.length" x-cloak class="flex flex-wrap items-center justify-between gap-3 border-b border-slate-200 bg-brand-50 px-4 py-2.5">
                    <span class="text-sm font-medium text-brand-800"><span x-text="selected.length"></span> Selected</span>
                    <x-button type="button" variant="danger" size="sm" icon="trash" x-on:click="$dispatch('open-modal', 'bulk-del-runs')">Delete Selected</x-button>
                </div>

                <x-table flush>
                    <thead>
                        <tr>
                            <th class="w-10">
                                <button type="button" role="switch" :aria-checked="allOn.toString()" x-on:click="toggleAll()"
                                    :class="allOn ? 'bg-brand-600' : 'bg-slate-300'"
                                    class="relative inline-flex h-6 w-11 shrink-0 items-center rounded-full transition-colors align-middle" aria-label="Select All">
                                    <span :class="allOn ? 'translate-x-6' : 'translate-x-1'" class="inline-block h-4 w-4 transform rounded-full bg-white shadow transition-transform"></span>
                                </button>
                            </th>
                            <th>Server / Scan Job</th>
                            <th>Status</th>
                            <th>Hardening Score</th>
                            <th class="text-right">When</th>
                        </tr>
                    </thead>
                    <tbody>
                        @foreach ($runs as $r)
                            <tr class="cursor-pointer" onclick="window.location='{{ route('runs.show', $r) }}'">
                                <td onclick="event.stopPropagation()">@include('jobs._select-toggle', ['id' => $r->id])</td>
                                <td>
                                    <div class="font-medium text-slate-900 truncate">{{ $r->job?->host?->name ?? '—' }}</div>
                                    <div class="text-xs text-slate-500 truncate">{{ $r->job?->name ?? '—' }}</div>
                                </td>
                                <td><x-badge :color="$badge[$r->status] ?? 'neutral'" dot>{{ $label[$r->status] ?? ucfirst($r->status) }}</x-badge></td>
                                <td>
                                    @if ($r->score !== null)
                                        <x-badge :color="$scoreColor($r->score)">{{ $r->score }}/100</x-badge>
                                    @else
                                        <span class="text-slate-400 text-sm">—</span>
                                    @endif
                                </td>
                                <td class="text-right text-slate-500" data-tip="{{ $r->created_at?->format('M j, Y g:i A') }}">{{ $r->created_at?->diffForHumans() }}</td>
                            </tr>
                        @endforeach
                    </tbody>
                </x-table>

                {{-- Delete confirm modal (never a native confirm). --}}
                <x-modal name="bulk-del-runs" title="Delete Selected Scans?" icon="warning" tone="danger" maxWidth="max-w-md">
                    This permanently removes <span x-text="selected.length"></span> scan record(s) and every finding attached to them. This cannot be undone.
                    <x-slot:footer>
                        <x-button variant="secondary" size="sm" x-on:click="$dispatch('close-modal', 'bulk-del-runs')">Cancel</x-button>
                        <x-button variant="danger" size="sm" icon="trash" x-on:click="$dispatch('close-modal', 'bulk-del-runs'); submitBulk()">Delete Selected</x-button>
                    </x-slot:footer>
                </x-modal>
            </div>
        @endif
    </x-card>

    @if ($runs->hasPages())
        <div class="mt-4">{{ $runs->links() }}</div>
    @endif
</x-layouts.app>
