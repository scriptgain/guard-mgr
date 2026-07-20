@php
    use Illuminate\Support\Str;

    $badge = ['success' => 'success', 'running' => 'info', 'queued' => 'neutral', 'warn' => 'warn', 'failed' => 'danger'];
    $label = ['success' => 'Passed', 'running' => 'Running', 'queued' => 'Queued', 'warn' => 'Warnings', 'failed' => 'Failed'];

    // Hardening score -> band color. Null until Phase 2's scan engine reports one.
    $scoreBand = function ($s) {
        if ($s === null) return ['#94a3b8', 'Pending'];
        if ($s >= 85) return ['#10b981', 'Strong'];
        if ($s >= 60) return ['#f59e0b', 'Needs work'];
        return ['#f43f5e', 'At risk'];
    };

    // KPI row — number + label + a meaningful one-line subtext, grouped with the icon.
    $kpis = [
        ['label' => 'Directors', 'value' => $stats['directors'], 'icon' => 'cloud',
            'sub' => 'Scan controllers', 'tone' => 'muted'],
        ['label' => 'Protected Servers', 'value' => $stats['hosts'], 'icon' => 'server',
            'sub' => $staleHosts ? $staleHosts . ' ' . Str::plural('agent', $staleHosts) . ' need attention' : 'All agents reporting in',
            'tone' => $staleHosts ? 'amber' : 'emerald'],
        ['label' => 'Active Scan Jobs', 'value' => $stats['jobs'], 'icon' => 'clock',
            'sub' => 'Scheduled and enabled', 'tone' => 'muted'],
        ['label' => 'Total Scans', 'value' => number_format($stats['scans']), 'icon' => 'shield',
            'sub' => 'Across all servers', 'tone' => 'muted'],
    ];
    $toneClass = ['muted' => 'text-slate-400', 'amber' => 'text-amber-600', 'emerald' => 'text-emerald-600'];

    // 14-day activity bar chart geometry (inline SVG, no chart library).
    $cw = 700; $ch = 150; $padT = 12; $padB = 22;
    $plotH = $ch - $padT - $padB;
    $baseY = $padT + $plotH;
    $n = max(1, count($activity));
    $slot = ($cw - 8) / $n;
    $barW = min(26, $slot * 0.62);
    $maxVal = max(1, max(array_column($activity, 'total') ?: [0]));

    // Hardening-score gauge (semicircle) geometry.
    $gaugeLen = 276.46; // ~ pi * r, r = 88
    [$scoreColor, $scoreLabel] = $scoreBand($hardeningScore);
    $gaugeDash = round(min(100, max(0, (int) ($hardeningScore ?? 0))) / 100 * $gaugeLen, 1);
@endphp

<x-layouts.app title="Dashboard">
    {{-- Brand accent bound to the runtime --color-brand-* var so a custom accent still applies. --}}
    <style>
        .bk-ok-fill { fill: var(--color-brand-500); }
        .bk-ok-stroke { stroke: var(--color-brand-500); }
        .bk-ok-bg { background-color: var(--color-brand-500); }
    </style>

    <x-page-header title="Dashboard" subtitle="Fleet security posture at a glance.">
        <x-slot:actions>
            <x-button variant="secondary" size="sm" icon="cloud" href="{{ route('directors.index') }}">Directors</x-button>
            <x-button size="sm" icon="plus" href="{{ route('jobs.create') }}">New Scan Job</x-button>
        </x-slot:actions>
    </x-page-header>

    {{-- KPI row --}}
    <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        @foreach ($kpis as $k)
            <div class="group relative flex flex-col overflow-hidden rounded-xl bg-white ring-1 ring-slate-200 shadow-sm transition hover:shadow-md hover:ring-brand-200">
                <span class="h-1 w-full bg-gradient-to-r from-brand-400 to-brand-600"></span>
                <div class="flex flex-1 items-center gap-4 p-5">
                    <span class="inline-flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-brand-50 text-brand-600 ring-1 ring-brand-200">
                        <x-icon :name="$k['icon']" class="h-5 w-5" />
                    </span>
                    <div class="ml-auto text-right">
                        <p class="text-2xl font-semibold tracking-tight text-slate-900 tabular">{{ $k['value'] }}</p>
                        <p class="mt-0.5 text-sm font-medium text-slate-600">{{ $k['label'] }}</p>
                        <p class="mt-0.5 text-xs font-medium {{ $toneClass[$k['tone']] }}">{{ $k['sub'] }}</p>
                    </div>
                </div>
            </div>
        @endforeach
    </div>

    {{-- Activity + hardening score --}}
    <div class="mt-4 grid grid-cols-1 lg:grid-cols-3 gap-4 items-stretch">
        {{-- Scan activity (signature visual) --}}
        <x-card title="Scan Activity" subtitle="Scans per day, last 14 days" class="lg:col-span-2 h-full">
            <x-slot:actions>
                @if ($successRate !== null)
                    <span class="inline-flex items-center gap-1.5 rounded-full bg-emerald-50 px-2.5 py-1 text-xs font-medium text-emerald-700 ring-1 ring-inset ring-emerald-200">
                        <x-icon name="check-circle" class="h-3.5 w-3.5" /> {{ $successRate }}% passed
                    </span>
                @endif
            </x-slot:actions>

            @if ($windowTotal === 0)
                <div class="flex h-40 flex-col items-center justify-center text-center">
                    <span class="inline-flex h-10 w-10 items-center justify-center rounded-lg bg-slate-100 text-slate-400"><x-icon name="clock" class="h-5 w-5" /></span>
                    <p class="mt-3 text-sm text-slate-500">No scans in the last 14 days.</p>
                </div>
            @else
                <svg viewBox="0 0 {{ $cw }} {{ $ch }}" width="100%" class="block h-auto" role="img" aria-label="Scans per day over the last 14 days">
                    {{-- baseline --}}
                    <line x1="4" y1="{{ $baseY + 0.5 }}" x2="{{ $cw - 4 }}" y2="{{ $baseY + 0.5 }}" stroke="#e2e8f0" stroke-width="1" />
                    @foreach ($activity as $i => $d)
                        @php
                            $cx = 4 + $slot * $i + $slot / 2;
                            $x = round($cx - $barW / 2, 1);
                            $h = $d['total'] ? max(3, round($d['total'] / $maxVal * $plotH, 1)) : 0;
                            $sh = $d['total'] ? round($d['success'] / $d['total'] * $h, 1) : 0;
                            $ih = round($h - $sh, 1);
                        @endphp
                        @if ($h === 0.0 || $h === 0)
                            <rect x="{{ $x }}" y="{{ $baseY - 3 }}" width="{{ round($barW, 1) }}" height="3" rx="1.5" fill="#e2e8f0" />
                        @else
                            @if ($ih > 0)
                                <rect x="{{ $x }}" y="{{ round($baseY - $h, 1) }}" width="{{ round($barW, 1) }}" height="{{ $ih }}" rx="2" fill="#f43f5e" />
                            @endif
                            @if ($sh > 0)
                                <rect x="{{ $x }}" y="{{ round($baseY - $sh, 1) }}" width="{{ round($barW, 1) }}" height="{{ $sh }}" rx="2" class="bk-ok-fill" />
                            @endif
                        @endif
                        @php
                            $fail = $d['total'] - $d['success'];
                            $tip = $d['label'] . ' — ' . $d['total'] . ' scan' . ($d['total'] == 1 ? '' : 's');
                            if ($d['total']) {
                                $tip .= ' (' . $d['success'] . ' passed' . ($fail ? ', ' . $fail . ' failed/warn' : '') . ')';
                            }
                        @endphp
                        <rect x="{{ round(4 + $slot * $i, 1) }}" y="0" width="{{ round($slot, 1) }}" height="{{ round($baseY, 1) }}" fill="transparent" style="cursor:default" data-tip="{{ $tip }}" />
                        @if ($i === 0 || $i === intdiv($n, 2) || $i === $n - 1)
                            <text x="{{ round($cx, 1) }}" y="{{ $ch - 6 }}" text-anchor="{{ $i === 0 ? 'start' : ($i === $n - 1 ? 'end' : 'middle') }}" fill="#94a3b8" style="font-size:11px">{{ $d['label'] }}</text>
                        @endif
                    @endforeach
                </svg>

                <div class="mt-4 flex flex-wrap items-center gap-x-5 gap-y-2 text-xs font-medium text-slate-500">
                    <span class="inline-flex items-center gap-1.5"><span class="h-2.5 w-2.5 rounded-sm bk-ok-bg"></span> Passed</span>
                    <span class="inline-flex items-center gap-1.5"><span class="h-2.5 w-2.5 rounded-sm" style="background-color:#f43f5e"></span> Failed or warning</span>
                    <span class="ml-auto tabular text-slate-400">{{ number_format($windowTotal) }} {{ Str::plural('scan', $windowTotal) }} total</span>
                </div>
            @endif

            <x-slot:footer>
                <div class="flex items-center gap-6">
                    <div class="flex items-center gap-2.5">
                        <span class="inline-flex h-9 w-9 items-center justify-center rounded-lg {{ $failed24h ? 'bg-rose-50 text-rose-600 ring-1 ring-rose-200' : 'bg-white text-slate-400 ring-1 ring-slate-200' }}"><x-icon name="warning" class="h-4 w-4" /></span>
                        <div>
                            <p class="text-lg font-semibold leading-tight tabular {{ $failed24h ? 'text-rose-600' : 'text-slate-900' }}">{{ $failed24h }}</p>
                            <p class="text-xs text-slate-500">Failed scans (24h)</p>
                        </div>
                    </div>
                    <span class="h-9 w-px bg-slate-200"></span>
                    <div class="flex items-center gap-2.5">
                        <span class="inline-flex h-9 w-9 items-center justify-center rounded-lg {{ $staleHosts ? 'bg-amber-50 text-amber-600 ring-1 ring-amber-200' : 'bg-white text-slate-400 ring-1 ring-slate-200' }}"><x-icon name="server" class="h-4 w-4" /></span>
                        <div>
                            <p class="text-lg font-semibold leading-tight tabular {{ $staleHosts ? 'text-amber-600' : 'text-slate-900' }}">{{ $staleHosts }}</p>
                            <p class="text-xs text-slate-500">Stale agents · 10+ min</p>
                        </div>
                    </div>
                </div>
            </x-slot:footer>
        </x-card>

        {{-- Hardening score gauge (Phase 1 stub — filled by the scan engine in Phase 2) --}}
        <x-card title="Hardening Score" subtitle="Fleet average, latest scans" class="h-full">
            <div>
                <div class="mx-auto w-full max-w-[240px]">
                    <svg viewBox="0 0 200 122" width="100%" role="img" aria-label="Hardening score {{ $hardeningScore ?? 'pending' }}">
                        <path d="M12 110 A88 88 0 0 1 188 110" fill="none" stroke="#e2e8f0" stroke-width="14" stroke-linecap="round" />
                        @if ($hardeningScore !== null)
                            <path d="M12 110 A88 88 0 0 1 188 110" fill="none" stroke-width="14" stroke-linecap="round"
                                stroke="{{ $scoreColor }}" stroke-dasharray="{{ $gaugeDash }} 1000" />
                            <text x="100" y="92" text-anchor="middle" fill="#0f172a" style="font-size:38px;font-weight:700;font-variant-numeric:tabular-nums">{{ $hardeningScore }}</text>
                            <text x="100" y="110" text-anchor="middle" fill="#94a3b8" style="font-size:11px;letter-spacing:.02em">/ 100</text>
                        @else
                            <text x="100" y="94" text-anchor="middle" fill="#94a3b8" style="font-size:22px;font-weight:600">—</text>
                        @endif
                    </svg>
                </div>
                <div class="mt-1 flex items-center justify-center gap-2">
                    <span class="inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-medium ring-1 ring-inset"
                          style="color:{{ $scoreColor }};background-color:{{ $scoreColor }}14;border-color:{{ $scoreColor }}33">
                        <span class="h-1.5 w-1.5 rounded-full" style="background-color:{{ $scoreColor }}"></span> {{ $scoreLabel }}
                    </span>
                </div>
                @if ($hardeningScore === null)
                    <p class="mt-3 text-center text-xs text-slate-400">
                        No scored scans yet. Run a scan to compute a hardening score.
                    </p>
                @else
                    <p class="mt-1 text-center text-xs text-slate-400">Fleet average across {{ $serverScores->count() }} scored {{ Str::plural('server', $serverScores->count()) }}</p>
                    <ul class="mt-3 space-y-2 border-t border-slate-100 pt-3">
                        @foreach ($serverScores as $s)
                            @php [$sc] = $scoreBand($s->latest_score); @endphp
                            <li class="flex items-center gap-3 text-sm">
                                <a href="{{ route('hosts.show', $s) }}" class="min-w-0 flex-1 truncate font-medium text-slate-700 hover:text-brand-700">{{ $s->name }}</a>
                                <div class="h-1.5 w-20 shrink-0 overflow-hidden rounded-full bg-slate-100">
                                    <span class="block h-full rounded-full" style="width:{{ max(2, min(100, $s->latest_score)) }}%;background-color:{{ $sc }}"></span>
                                </div>
                                <span class="w-8 shrink-0 text-right font-semibold tabular" style="color:{{ $sc }}">{{ $s->latest_score }}</span>
                            </li>
                        @endforeach
                    </ul>
                @endif
            </div>
        </x-card>
    </div>

    @if ($updateHosts->isNotEmpty())
        <div class="mt-6">
            <x-card title="Patch Status" :subtitle="$rebootCount ? $rebootCount . ' ' . Str::plural('Server', $rebootCount) . ' need a reboot' : 'Servers with pending updates'" flush>
                <x-table flush>
                    <thead><tr><th>Server</th><th>Updates</th><th>Security</th><th>Kernel</th><th>Reboot</th><th class="text-right">Action</th></tr></thead>
                    <tbody>
                        @foreach ($updateHosts as $h)
                            <tr>
                                <td class="font-medium text-slate-900"><a href="{{ route('hosts.show', $h) }}" class="hover:text-brand-700">{{ $h->name }}</a></td>
                                <td class="tabular">{{ $h->updates_available ?? '—' }}</td>
                                <td class="tabular">@if (($h->security_updates ?? 0) > 0)<span class="font-semibold text-amber-600">{{ $h->security_updates }}</span>@else <span class="text-slate-400">0</span>@endif</td>
                                <td>@if ($h->kernel_update)<x-badge color="danger" dot>Update</x-badge>@else <span class="text-slate-400">—</span>@endif</td>
                                <td>@if ($h->reboot_required)<x-badge color="danger" dot>Required</x-badge>@else <span class="text-slate-400">—</span>@endif</td>
                                <td class="text-right"><a href="{{ route('hosts.show', $h) }}" class="text-xs font-medium text-brand-700 hover:text-brand-800">Manage</a></td>
                            </tr>
                        @endforeach
                    </tbody>
                </x-table>
            </x-card>
        </div>
    @endif

    @if ($attention->isNotEmpty())
        <div class="mt-6">
            <x-card title="Needs Attention" subtitle="Recent failed or warning scans" flush>
                <div x-data="{ selected: [], confirming: false, allIds: [{{ $attention->pluck('id')->implode(',') }}], submitBulk() { const f = this.$refs.bulkForm; f.querySelectorAll('input.js-dyn').forEach(n => n.remove()); this.selected.forEach(id => { const i = document.createElement('input'); i.type='hidden'; i.name='ids[]'; i.value=id; i.className='js-dyn'; f.appendChild(i); }); (f.requestSubmit ? f.requestSubmit() : f.submit()); } }">
                    <form method="POST" action="{{ route('runs.bulk-destroy') }}" x-ref="bulkForm" class="hidden">@csrf @method('DELETE')</form>
                    <div x-show="selected.length" x-cloak class="flex flex-wrap items-center justify-between gap-3 border-b border-slate-200 bg-brand-50 px-4 py-2.5">
                        <span class="text-sm font-medium text-brand-800"><span x-text="selected.length"></span> selected</span>
                        <div class="flex items-center gap-2">
                            <template x-if="! confirming"><x-button type="button" variant="danger" size="sm" icon="trash" x-on:click="confirming = true">Delete Selected</x-button></template>
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
                            <th class="w-10">Select</th>
                            <th>Server / Scan Job</th><th>Status</th><th class="text-right">When</th>
                        </tr></thead>
                        <tbody>
                            @foreach ($attention as $r)
                                <tr class="cursor-pointer" onclick="window.location='{{ route('runs.show', $r) }}'">
                                    <td onclick="event.stopPropagation()">@include('jobs._select-toggle', ['id' => $r->id])</td>
                                    <td>
                                        <div class="font-medium text-slate-900 truncate">{{ $r->job?->host?->name ?? '—' }}</div>
                                        <div class="text-xs text-slate-500 truncate">{{ $r->job?->name ?? '—' }}</div>
                                    </td>
                                    <td><x-badge :color="$r->status === 'failed' ? 'danger' : 'warn'" dot>{{ $label[$r->status] ?? ucfirst($r->status) }}</x-badge></td>
                                    <td class="text-right text-slate-500" data-tip="{{ $r->created_at?->format('M j, Y g:i A') }}">{{ $r->created_at?->diffForHumans() }}</td>
                                </tr>
                            @endforeach
                        </tbody>
                    </x-table>
                </div>
            </x-card>
        </div>
    @endif

    <div class="mt-6">
        <x-card title="Recent Scans" subtitle="Latest scan activity across all servers" :flush="$runs->isNotEmpty()">
            <x-slot:actions>
                <x-button variant="ghost" size="sm" href="{{ route('runs.index') }}">View All</x-button>
            </x-slot:actions>

            @if ($runs->isEmpty())
                <x-empty-state icon="shield" title="No Scans Yet" description="Add a server and a scan job, then run it to see activity here.">
                    <x-slot:action><x-button icon="plus" href="{{ route('directors.index') }}">Add a Director</x-button></x-slot:action>
                </x-empty-state>
            @else
                <div x-data="{ selected: [], confirming: false, allIds: [{{ $runs->pluck('id')->implode(',') }}], submitBulk() { const f = this.$refs.bulkForm; f.querySelectorAll('input.js-dyn').forEach(n => n.remove()); this.selected.forEach(id => { const i = document.createElement('input'); i.type='hidden'; i.name='ids[]'; i.value=id; i.className='js-dyn'; f.appendChild(i); }); (f.requestSubmit ? f.requestSubmit() : f.submit()); } }">
                    <form method="POST" action="{{ route('runs.bulk-destroy') }}" x-ref="bulkForm" class="hidden">@csrf @method('DELETE')</form>
                    <div x-show="selected.length" x-cloak class="flex flex-wrap items-center justify-between gap-3 border-b border-slate-200 bg-brand-50 px-4 py-2.5">
                        <span class="text-sm font-medium text-brand-800"><span x-text="selected.length"></span> selected</span>
                        <div class="flex items-center gap-2">
                            <template x-if="! confirming"><x-button type="button" variant="danger" size="sm" icon="trash" x-on:click="confirming = true">Delete Selected</x-button></template>
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
                        <thead>
                            <tr><th class="w-10">Select</th><th>Server / Scan Job</th><th>Status</th><th>Score</th><th class="text-right">When</th></tr>
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
                                    <td class="tabular text-slate-600">{{ $r->score !== null ? $r->score . '/100' : '—' }}</td>
                                    <td class="text-right text-slate-500" data-tip="{{ $r->created_at?->format('M j, Y g:i A') }}">{{ $r->created_at?->diffForHumans() }}</td>
                                </tr>
                            @endforeach
                        </tbody>
                    </x-table>
                </div>
            @endif
        </x-card>
    </div>
</x-layouts.app>
