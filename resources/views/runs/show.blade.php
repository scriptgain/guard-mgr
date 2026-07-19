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
    $openCount = $run->findings->where('status', 'open')->count();

    // Engine metadata (label + category) from the single source of truth.
    $engines = \App\Http\Controllers\JobController::ENGINES;
    $engineLabel = collect($engines)->mapWithKeys(fn ($m, $k) => [$k => $m[0]])->all();
    $engineCategory = collect($engines)->mapWithKeys(fn ($m, $k) => [$k => $m[2] ?? 'Other'])->all();
    $categoryOrder = \App\Http\Controllers\JobController::ENGINE_CATEGORIES;

    // Group findings by engine and present engines in category order, then key.
    $byEngine = $run->findings->groupBy(fn ($f) => $f->engine ?: 'other');
    $engineKeys = $byEngine->keys()->sortBy(function ($k) use ($engineCategory, $categoryOrder) {
        $ci = array_search($engineCategory[$k] ?? 'Other', $categoryOrder);
        return sprintf('%02d-%s', $ci === false ? 99 : $ci, $k);
    })->values();

    // Sort a set of findings: open first, then by severity.
    $sortFindings = fn ($items) => $items->sortBy(fn ($f) => (($f->status ?? 'open') === 'open' ? '0' : '1') . '-' . array_search($f->severity, $order))->values();

    // Per-engine badge data: total count + whether any OPEN high/critical exists.
    $engineStats = [];
    foreach ($engineKeys as $ek) {
        $items = $byEngine[$ek] ?? collect();
        $engineStats[$ek] = [
            'total' => $items->count(),
            'hasHigh' => $items->first(fn ($f) => ($f->status ?? 'open') === 'open' && in_array($f->severity, ['critical', 'high'])) !== null,
            'worst' => (function () use ($items, $order) {
                foreach ($order as $s) {
                    if ($items->first(fn ($f) => ($f->status ?? 'open') === 'open' && $f->severity === $s)) return array_search($s, $order);
                }
                return 99;
            })(),
        ];
    }
    // Default to the engine tab with the worst OPEN severity, else the first.
    $defaultTab = collect($engineStats)->sortBy('worst')->keys()->first() ?? ($engineKeys->first() ?? '');

    // Worst severity in a set, for the section accent dot.
    $worst = function ($items) use ($order) {
        foreach ($order as $s) {
            if ($items->firstWhere('severity', $s)) return $s;
        }
        return 'info';
    };

    // Pull the leading "<site>: " path out of a WordPress finding's detail so the
    // WordPress section can group per site.
    $wpSite = function ($f) {
        if (preg_match('#^(/\S.*?):\s#', (string) $f->detail, $m)) return $m[1];
        return 'WordPress';
    };

    // Can this Server run agent-side fixes? (Local Server or enrolled agent.)
    $canFix = (bool) $run->job?->host?->canRemediate();
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

    {{-- Hardening score + summary — always at the top, above the tabs. --}}
    <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
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

        <x-card title="Summary" class="lg:col-span-2">
            <div class="grid grid-cols-2 sm:grid-cols-4 gap-4 mb-5">
                <div><p class="text-xs text-slate-500">Status</p><p class="mt-1"><x-badge :color="$statusBadge[$run->status] ?? 'neutral'" dot>{{ $statusLabel[$run->status] ?? ucfirst($run->status) }}</x-badge></p></div>
                <div><p class="text-xs text-slate-500">Open Findings</p><p class="mt-1 text-lg font-semibold tabular text-slate-900">{{ $openCount }} <span class="text-xs font-normal text-slate-400">/ {{ $run->findings->count() }}</span></p></div>
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

    {{-- A single finding row, reused by the engine + WordPress sections. --}}
    @php
        $renderFinding = function ($f) use ($sevMeta, $canFix) {
            [$c, $lbl, $hex] = $sevMeta[in_array($f->severity, array_keys($sevMeta)) ? $f->severity : 'info'];
            return view('runs._finding', ['f' => $f, 'lbl' => $lbl, 'hex' => $hex, 'canFix' => $canFix]);
        };
    @endphp

    @if ($run->findings->isEmpty() && in_array($run->status, ['queued', 'running']))
        {{-- Live progress: poll progress.json every 3s; reload into the tabbed
             report the moment the scan reaches a terminal state. --}}
        <div class="mt-6"
             x-data="{
                url: @js(route('runs.progress', $run)),
                status: @js($run->status),
                pct: {{ (int) ($run->progress_pct ?? 0) }},
                engine: @js($run->current_engine ?? ''),
                log: @js($run->progress_log ?? ''),
                findings: 0,
                timer: null,
                init() { this.poll(); this.timer = setInterval(() => this.poll(), 3000); },
                async poll() {
                    try {
                        const r = await fetch(this.url, { headers: { 'Accept': 'application/json' } });
                        if (!r.ok) return;
                        const d = await r.json();
                        this.status = d.status;
                        this.pct = d.progress_pct ?? this.pct;
                        this.engine = d.current_engine ?? '';
                        this.log = d.progress_log ?? this.log;
                        this.findings = d.findings_count ?? 0;
                        this.$nextTick(() => { const b = this.$refs.logbox; if (b) b.scrollTop = b.scrollHeight; });
                        if (['success', 'warn', 'failed'].includes(this.status)) { clearInterval(this.timer); window.location.reload(); }
                    } catch (e) {}
                }
             }">
            <x-card>
                <div class="flex items-center justify-between gap-3">
                    <div class="flex items-center gap-2.5">
                        <span class="inline-block h-4 w-4 rounded-full border-2 border-brand-600 border-t-transparent animate-spin"></span>
                        <span class="font-medium text-slate-900" x-text="status === 'queued' ? 'Queued — Waiting for the Agent' : 'Scan In Progress'"></span>
                        <span x-show="engine" x-cloak class="rounded-full bg-slate-100 px-2 py-0.5 text-xs font-medium text-slate-600">Engine: <span x-text="engine"></span></span>
                    </div>
                    <span class="text-sm font-semibold tabular-nums text-brand-700" x-text="pct + '%'"></span>
                </div>

                <div class="mt-3 h-2 w-full overflow-hidden rounded-full bg-slate-100">
                    <div class="h-full rounded-full bg-brand-600 transition-all duration-500 ease-out" :style="`width:${pct}%`"></div>
                </div>

                <p class="mt-2 text-xs text-slate-500">
                    <span x-show="status === 'queued'">The scan is queued; it starts on the agent's next poll.</span>
                    <span x-show="status !== 'queued'"><span x-text="findings"></span> finding(s) so far · live output below</span>
                </p>

                {{-- Fixed-height, auto-scrolling log tail — never grows the page. --}}
                <pre x-ref="logbox" x-text="log || 'Waiting for the agent to start…'"
                     class="mt-3 h-64 overflow-y-auto rounded-lg bg-chrome p-4 text-xs leading-relaxed text-slate-100 whitespace-pre-wrap"></pre>
            </x-card>
        </div>
    @elseif ($run->findings->isEmpty())
        <div class="mt-6">
            <x-card>
                <x-empty-state icon="check-circle" title="No Findings" description="The selected engines did not raise any findings on this scan." />
            </x-card>
        </div>
    @else
        {{-- Tabbed findings — one tab per engine that ran. --}}
        <div class="mt-6" x-data="{
                tab: @js($defaultTab),
                sel: [],
                confirmOp: null,
                toggle(id){ const i = this.sel.indexOf(id); i < 0 ? this.sel.push(id) : this.sel.splice(i, 1); },
                setTab(t){ this.tab = t; this.sel = []; this.confirmOp = null; },
                pick(ids){ this.sel = ids; },
                ask(op){ if (this.sel.length) this.confirmOp = op; },
                go(){ this.$refs.bop.value = this.confirmOp; (this.$refs.bform.requestSubmit ? this.$refs.bform.requestSubmit() : this.$refs.bform.submit()); },
                opLabel(){ return { apply: 'Apply Fix to', 'mark-fixed': 'Mark as Fixed', dismiss: 'Dismiss' }[this.confirmOp] || ''; }
            }" x-cloak>

            <x-card flush>
                {{-- Tab bar --}}
                <div class="border-b border-slate-200 px-3">
                    <nav class="-mb-px flex gap-1 overflow-x-auto" aria-label="Scan engines">
                        @foreach ($engineKeys as $ek)
                            @php $st = $engineStats[$ek]; @endphp
                            <button type="button" @click="setTab('{{ $ek }}')"
                                :class="tab === '{{ $ek }}' ? 'border-brand-600 text-brand-700' : 'border-transparent text-slate-500 hover:text-slate-700 hover:border-slate-300'"
                                class="group inline-flex items-center gap-2 whitespace-nowrap border-b-2 px-3 py-3 text-sm font-medium transition">
                                {{ $engineLabel[$ek] ?? $ek }}
                                <span :class="tab === '{{ $ek }}' ? 'bg-brand-100 text-brand-700' : 'bg-slate-100 text-slate-500'"
                                      class="rounded-full px-1.5 py-0.5 text-xs font-semibold tabular-nums">{{ $st['total'] }}</span>
                                @if ($st['hasHigh'])
                                    <span class="h-1.5 w-1.5 rounded-full bg-rose-500" title="Has Open High or Critical Findings"></span>
                                @endif
                            </button>
                        @endforeach
                    </nav>
                </div>

                {{-- Bulk action bar (operates within the active tab). --}}
                <div class="flex flex-wrap items-center gap-2 border-b border-slate-100 bg-slate-50/70 px-5 py-2.5" x-show="sel.length" x-cloak>
                    <span class="text-sm font-medium text-slate-700"><span x-text="sel.length"></span> selected</span>
                    <div class="ml-auto flex items-center gap-2">
                        @if ($canFix)
                            <x-button type="button" size="sm" icon="bolt" x-on:click="ask('apply')">Fix Selected</x-button>
                        @endif
                        <x-button type="button" size="sm" variant="secondary" icon="check" x-on:click="ask('mark-fixed')">Mark as Fixed</x-button>
                        <x-button type="button" size="sm" variant="secondary" icon="x" x-on:click="ask('dismiss')">Dismiss</x-button>
                        <x-button type="button" size="sm" variant="ghost" x-on:click="sel = []">Clear</x-button>
                    </div>
                    {{-- Hidden bulk form: ids + op submitted after confirm. --}}
                    <form method="POST" action="{{ route('findings.bulk', $run) }}" x-ref="bform" class="hidden">
                        @csrf
                        <input type="hidden" name="op" x-ref="bop">
                        <template x-for="id in sel" :key="id"><input type="hidden" name="ids[]" :value="id"></template>
                    </form>
                </div>

                {{-- Engine panels --}}
                @foreach ($engineKeys as $ek)
                    @php
                        $items = $sortFindings($byEngine[$ek] ?? collect());
                        $openIds = $items->where('status', 'open')->pluck('id')->values()->all();
                        $safeIds = $items->filter(fn ($f) => ($f->status ?? 'open') === 'open' && $f->fixable && ! $f->is_risky && $f->fix_kind)->pluck('id')->values()->all();
                        $cat = $engineCategory[$ek] ?? 'Other';
                    @endphp
                    <div x-show="tab === '{{ $ek }}'" x-cloak>
                        <div class="flex flex-wrap items-center gap-2 px-5 py-2.5 text-xs text-slate-500">
                            <span class="rounded-full bg-slate-100 px-2 py-0.5 font-medium text-slate-500">{{ $cat }}</span>
                            <span>{{ $items->count() }} finding{{ $items->count() === 1 ? '' : 's' }}</span>
                            <span class="ml-auto flex items-center gap-3">
                                @if ($canFix && count($safeIds))
                                    <button type="button" class="inline-flex items-center gap-1 text-xs font-semibold text-brand-700 hover:text-brand-800" @click="pick(@js($safeIds)); ask('apply')">
                                        <x-icon name="bolt" class="h-3.5 w-3.5" /> Fix All Safe ({{ count($safeIds) }})
                                    </button>
                                @endif
                                @if (count($openIds))
                                    <button type="button" class="text-xs font-medium text-brand-700 hover:text-brand-800" @click="pick(@js($openIds))">Select All Open ({{ count($openIds) }})</button>
                                @endif
                            </span>
                        </div>

                        @if ($ek === 'wordpress')
                            @php $bySite = $items->groupBy($wpSite); @endphp
                            @foreach ($bySite as $site => $siteItems)
                                <div class="border-t border-slate-100">
                                    <div class="flex items-center gap-2 bg-slate-50/70 px-5 py-2">
                                        <x-icon name="globe" class="h-4 w-4 text-slate-400" />
                                        <span class="font-mono text-xs text-slate-600">{{ $site }}</span>
                                        <span class="text-xs text-slate-400">· {{ $siteItems->count() }}</span>
                                    </div>
                                    <ul class="divide-y divide-slate-100">
                                        @foreach ($sortFindings($siteItems) as $f){!! $renderFinding($f) !!}@endforeach
                                    </ul>
                                </div>
                            @endforeach
                        @else
                            <ul class="divide-y divide-slate-100 border-t border-slate-100">
                                @foreach ($items as $f){!! $renderFinding($f) !!}@endforeach
                            </ul>
                        @endif
                    </div>
                @endforeach
            </x-card>

            {{-- Bulk confirm modal (no native dialogs). --}}
            <div x-show="confirmOp" x-cloak class="fixed inset-0 z-50 flex items-center justify-center p-4"
                 x-transition.opacity @keydown.escape.window="confirmOp = null">
                <div class="absolute inset-0 bg-slate-900/40" @click="confirmOp = null"></div>
                <div class="relative w-full max-w-md rounded-xl bg-white p-5 shadow-xl ring-1 ring-slate-200">
                    <h3 class="text-base font-semibold text-slate-900">Confirm Bulk Action</h3>
                    <p class="mt-2 text-sm text-slate-600">
                        <span x-text="opLabel()"></span> <span x-text="sel.length"></span> selected finding(s)?
                        <span x-show="confirmOp === 'apply'" class="mt-2 block text-slate-500">Risky fixes change system configuration; GuardMGR backs up each edited file first so changes can be reverted.</span>
                    </p>
                    <div class="mt-5 flex items-center justify-end gap-2">
                        <x-button type="button" variant="secondary" size="sm" x-on:click="confirmOp = null">Cancel</x-button>
                        <x-button type="button" size="sm" x-on:click="go()">Confirm</x-button>
                    </div>
                </div>
            </div>
        </div>
    @endif

    @if ($run->log)
        <div class="mt-6">
            <x-card title="Scan Log">
                <pre class="rounded-lg bg-chrome text-slate-100 text-xs p-4 overflow-x-auto whitespace-pre-wrap">{{ $run->log }}</pre>
            </x-card>
        </div>
    @endif
</x-layouts.app>
