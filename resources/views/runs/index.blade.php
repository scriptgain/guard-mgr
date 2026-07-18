@php
    // Scan status -> chip color + label.
    $badge = ['success' => 'success', 'running' => 'info', 'queued' => 'neutral', 'warn' => 'warn', 'failed' => 'danger'];
    $label = ['success' => 'Passed', 'running' => 'Running', 'queued' => 'Queued', 'warn' => 'Warnings', 'failed' => 'Failed'];

    // Hardening score -> chip color. Null until Phase 2's engine reports one.
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
                description="Add a server and a scan job, then run it to see hardening results here.">
                <x-slot:action><x-button icon="plus" href="{{ route('jobs.create') }}">New Scan Job</x-button></x-slot:action>
            </x-empty-state>
        @else
            <x-table flush>
                <thead>
                    <tr>
                        <th>Server / Scan Job</th>
                        <th>Status</th>
                        <th>Hardening Score</th>
                        <th class="text-right">When</th>
                    </tr>
                </thead>
                <tbody>
                    @foreach ($runs as $r)
                        <tr class="cursor-pointer" onclick="window.location='{{ route('runs.show', $r) }}'">
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
        @endif
    </x-card>

    @if ($runs->hasPages())
        <div class="mt-4">{{ $runs->links() }}</div>
    @endif
</x-layouts.app>
