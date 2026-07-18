@php
    $statusBadge = ['success' => 'success', 'running' => 'info', 'queued' => 'neutral', 'warn' => 'warn', 'failed' => 'danger'];
    $statusLabel = ['success' => 'Passed', 'running' => 'Running', 'queued' => 'Queued', 'warn' => 'Warnings', 'failed' => 'Failed'];
    $dur = ($run->started_at && $run->finished_at) ? $run->started_at->diffForHumans($run->finished_at, true) : '—';

    // Score band: color + verbal label for the big number.
    $band = function ($s) {
        if ($s === null) return ['#94a3b8', 'Pending'];
        if ($s >= 85) return ['#10b981', 'Strong'];
        if ($s >= 60) return ['#f59e0b', 'Needs Work'];
        return ['#f43f5e', 'At Risk'];
    };
    [$scoreColor, $scoreLabel] = $band($run->score);
    $gaugeLen = 276.46;
    $gaugeDash = round(min(100, max(0, (int) ($run->score ?? 0))) / 100 * $gaugeLen, 1);

    // Findings grouped by severity, in display order.
    $order = ['critical', 'high', 'medium', 'low', 'info'];
    $sevMeta = [
        'critical' => ['danger', 'Critical', '#dc2626'],
        'high' => ['danger', 'High', '#f43f5e'],
        'medium' => ['warn', 'Medium', '#f59e0b'],
        'low' => ['info', 'Low', '#3b82f6'],
        'info' => ['neutral', 'Info', '#64748b'],
    ];
    $grouped = $run->findings->groupBy('severity');
    $counts = collect($order)->mapWithKeys(fn ($s) => [$s => ($grouped[$s] ?? collect())->count()]);
    $engineLabel = ['lynis' => 'Lynis', 'rkhunter' => 'rkhunter', 'ufw' => 'ufw'];
@endphp
<x-layouts.app :title="'Scan #' . $run->id">
    <x-page-header :title="'Scan Report #' . $run->id" icon="shield"
        :subtitle="($run->job?->host?->name ?? 'Server') . ' · ' . ($run->job?->name ?? 'Scan Job')">
        <x-slot:actions>
            @if ($run->job)<x-button variant="secondary" icon="clock" href="{{ route('jobs.show', $run->job) }}">Scan Job</x-button>@endif
            <x-delete-button :name="'del-run-' . $run->id" :action="route('runs.destroy', $run)"
                title="Delete Scan?" message="This removes the scan record and its findings." confirm="Delete" label="Delete Scan" />
        </x-slot:actions>
    </x-page-header>

    @if ($run->status === 'failed')
        <div class="mb-6"><x-alert type="danger" title="This Scan Failed">{{ $run->error ?: 'The agent could not complete the scan.' }}</x-alert></div>
    @endif

    <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {{-- Hardening score gauge --}}
        <x-card title="Hardening Score" subtitle="Computed from this scan">
            <div class="mx-auto w-full max-w-[240px]">
                <svg viewBox="0 0 200 122" width="100%" role="img" aria-label="Hardening score {{ $run->score ?? 'pending' }}">
                    <path d="M12 110 A88 88 0 0 1 188 110" fill="none" stroke="#e2e8f0" stroke-width="14" stroke-linecap="round" />
                    @if ($run->score !== null)
                        <path d="M12 110 A88 88 0 0 1 188 110" fill="none" stroke-width="14" stroke-linecap="round"
                            stroke="{{ $scoreColor }}" stroke-dasharray="{{ $gaugeDash }} 1000" />
                        <text x="100" y="92" text-anchor="middle" fill="#0f172a" style="font-size:38px;font-weight:700;font-variant-numeric:tabular-nums">{{ $run->score }}</text>
                        <text x="100" y="110" text-anchor="middle" fill="#94a3b8" style="font-size:11px">/ 100</text>
                    @else
                        <text x="100" y="94" text-anchor="middle" fill="#94a3b8" style="font-size:22px;font-weight:600">—</text>
                    @endif
                </svg>
            </div>
            <div class="mt-1 flex items-center justify-center">
                <span class="inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-medium ring-1 ring-inset"
                      style="color:{{ $scoreColor }};background-color:{{ $scoreColor }}14;border-color:{{ $scoreColor }}33">
                    <span class="h-1.5 w-1.5 rounded-full" style="background-color:{{ $scoreColor }}"></span> {{ $scoreLabel }}
                </span>
            </div>
        </x-card>

        {{-- Summary + severity breakdown --}}
        <x-card title="Summary" class="lg:col-span-2">
            <div class="grid grid-cols-2 sm:grid-cols-4 gap-4 mb-5">
                <div><p class="text-xs text-slate-500">Status</p><p class="mt-1"><x-badge :color="$statusBadge[$run->status] ?? 'neutral'" dot>{{ $statusLabel[$run->status] ?? ucfirst($run->status) }}</x-badge></p></div>
                <div><p class="text-xs text-slate-500">Findings</p><p class="mt-1 text-lg font-semibold tabular text-slate-900">{{ $run->findings->count() }}</p></div>
                <div><p class="text-xs text-slate-500">Duration</p><p class="mt-1 text-sm font-medium text-slate-700">{{ $dur }}</p></div>
                <div><p class="text-xs text-slate-500">Finished</p><p class="mt-1 text-sm font-medium text-slate-700">{{ $run->finished_at?->diffForHumans() ?? '—' }}</p></div>
            </div>
            <div class="flex flex-wrap gap-2">
                @foreach ($order as $sev)
                    @php [$c, $lbl, $hex] = $sevMeta[$sev]; @endphp
                    <span class="inline-flex items-center gap-1.5 rounded-full px-3 py-1 text-sm font-medium ring-1 ring-inset"
                          style="color:{{ $hex }};background-color:{{ $hex }}12;border-color:{{ $hex }}30">
                        <span class="h-1.5 w-1.5 rounded-full" style="background-color:{{ $hex }}"></span>
                        {{ $lbl }}: {{ $counts[$sev] }}
                    </span>
                @endforeach
            </div>
        </x-card>
    </div>

    {{-- Findings, grouped by severity --}}
    <div class="mt-6 space-y-6">
        @php $hasFindings = $run->findings->isNotEmpty(); @endphp
        @if (! $hasFindings)
            <x-card>
                @if (in_array($run->status, ['queued', 'running']))
                    <x-empty-state icon="clock" title="Scan In Progress" description="Findings appear here once the agent finishes and reports back." />
                @else
                    <x-empty-state icon="check-circle" title="No Findings" description="The selected engines did not raise any findings on this scan." />
                @endif
            </x-card>
        @else
            @foreach ($order as $sev)
                @php $items = $grouped[$sev] ?? collect(); @endphp
                @if ($items->isNotEmpty())
                    @php [$c, $lbl, $hex] = $sevMeta[$sev]; @endphp
                    <x-card :title="$lbl . ' (' . $items->count() . ')'" flush>
                        <x-slot:actions><span class="h-2.5 w-2.5 rounded-full" style="background-color:{{ $hex }}"></span></x-slot:actions>
                        <ul class="divide-y divide-slate-100">
                            @foreach ($items as $f)
                                <li class="px-5 py-4">
                                    <div class="flex flex-wrap items-start justify-between gap-3">
                                        <div class="min-w-0 flex-1">
                                            <p class="font-medium text-slate-900">{{ $f->title }}</p>
                                            @if ($f->detail)<p class="mt-1 text-sm text-slate-600 whitespace-pre-wrap">{{ $f->detail }}</p>@endif
                                            @if ($f->remediation)
                                                <p class="mt-2 text-sm text-slate-700"><span class="font-medium text-emerald-700">Remediation:</span> {{ $f->remediation }}</p>
                                            @endif
                                        </div>
                                        <div class="flex shrink-0 items-center gap-2">
                                            @if ($f->code)<span class="rounded-md bg-slate-100 px-2 py-0.5 font-mono text-xs text-slate-500">{{ $f->code }}</span>@endif
                                            @if ($f->engine)<x-badge color="neutral">{{ $engineLabel[$f->engine] ?? $f->engine }}</x-badge>@endif
                                        </div>
                                    </div>
                                </li>
                            @endforeach
                        </ul>
                    </x-card>
                @endif
            @endforeach
        @endif

        @if ($run->log)
            <x-card title="Scan Log">
                <pre class="rounded-lg bg-chrome text-slate-100 text-xs p-4 overflow-x-auto whitespace-pre-wrap">{{ $run->log }}</pre>
            </x-card>
        @endif
    </div>
</x-layouts.app>
