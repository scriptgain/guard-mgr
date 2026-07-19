{{-- One finding row with lifecycle actions.
     Expects: $f (Finding), $lbl (severity label), $hex (severity color),
              $canFix (bool — Server can run agent remediations).
     Must render inside the findings Alpine scope (provides `sel` + `toggle`). --}}
@php
    $status = $f->status ?? 'open';
    [$stColor, $stLabel] = \App\Models\Finding::statusMeta($status);
    $stHex = ['neutral' => '#64748b', 'info' => '#3b82f6', 'success' => '#10b981', 'warn' => '#f59e0b'][$stColor] ?? '#64748b';
    // Terminal (applied/fixed/dismissed) = resolved. "queued" is in-flight: not
    // resolved, but a fix is already dispatched so Apply Fix must be hidden.
    $resolved = in_array($status, \App\Models\Finding::RESOLVED, true);
    $queued = $status === 'queued';
    $riskNote = 'This changes system configuration on the Server. GuardMGR backs up the file first (a .guardmgr.bak-* copy) so the change can be reverted, then validates and applies it.';
@endphp
<li class="px-5 py-4 {{ $resolved ? 'bg-slate-50/60' : ($queued ? 'bg-amber-50/40' : '') }}">
    <div class="flex items-start gap-3">
        {{-- Bulk-select toggle switch (never a checkbox, per house style). --}}
        <button type="button" role="switch" :aria-checked="sel.includes({{ $f->id }}).toString()" @click="toggle({{ $f->id }})"
                :class="sel.includes({{ $f->id }}) ? 'bg-brand-600' : 'bg-slate-300'"
                class="relative mt-1 inline-flex h-5 w-9 shrink-0 items-center rounded-full transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-500/60"
                aria-label="Select finding">
            <span :class="sel.includes({{ $f->id }}) ? 'translate-x-4' : 'translate-x-1'"
                  class="inline-block h-3.5 w-3.5 transform rounded-full bg-white shadow transition-transform"></span>
        </button>

        <div class="min-w-0 flex-1">
            <div class="flex flex-wrap items-center gap-2">
                <span class="inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 text-xs font-medium ring-1 ring-inset"
                      style="color:{{ $hex }};background-color:{{ $hex }}12;border-color:{{ $hex }}30">
                    <span class="h-1.5 w-1.5 rounded-full" style="background-color:{{ $hex }}"></span>{{ $lbl }}
                </span>
                {{-- Lifecycle status badge --}}
                <span class="inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 text-xs font-medium ring-1 ring-inset"
                      style="color:{{ $stHex }};background-color:{{ $stHex }}12;border-color:{{ $stHex }}30">
                    <span class="h-1.5 w-1.5 rounded-full" style="background-color:{{ $stHex }}"></span>{{ $stLabel }}
                </span>
                <p class="font-medium text-slate-900 {{ $resolved ? 'line-through decoration-slate-300' : '' }}">{{ $f->title }}</p>
            </div>
            @if ($f->detail)<p class="mt-1 text-sm text-slate-600 whitespace-pre-wrap break-words">{{ $f->detail }}</p>@endif
            @if ($f->remediation)
                <p class="mt-2 text-sm text-slate-700"><span class="font-medium text-emerald-700">Remediation:</span> {{ $f->remediation }}</p>
            @endif
            @if ($resolved && $f->resolved_by)
                <p class="mt-1 text-xs text-slate-400">{{ $stLabel }} by {{ $f->resolved_by }} {{ $f->resolved_at?->diffForHumans() }}</p>
            @endif

            {{-- Per-finding actions --}}
            <div class="mt-3 flex flex-wrap items-center gap-2">
                @if (! $resolved)
                    @if ($queued)
                        {{-- Fix already dispatched — no re-click. --}}
                        <span class="inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-sm font-medium text-amber-700 bg-amber-50 ring-1 ring-inset ring-amber-200 cursor-not-allowed"
                              title="A fix has been dispatched to the agent; it applies on the next poll, then this flips to Applied.">
                            <x-icon name="clock" class="h-4 w-4" /> Fix Queued
                        </span>
                    @elseif ($f->fixable && $f->fix_kind)
                        @if ($canFix)
                            @if ($f->is_risky)
                                <x-confirm-action :name="'applyfix-' . $f->id" :action="route('findings.apply', $f)"
                                    title="Apply Risky Fix?" :message="$riskNote . ' Fix: ' . $f->fix_kind"
                                    confirm="Apply Fix" confirmIcon="bolt" confirmVariant="primary" tone="danger">
                                    <x-button type="button" size="sm" icon="bolt">Apply Fix</x-button>
                                </x-confirm-action>
                            @else
                                <form method="POST" action="{{ route('findings.apply', $f) }}">@csrf
                                    <x-button type="submit" size="sm" icon="bolt">Apply Fix</x-button>
                                </form>
                            @endif
                        @else
                            <span class="inline-flex items-center gap-1 text-xs text-slate-400" title="Apply Fix needs an enrolled agent or the local Server.">
                                <x-icon name="bolt" class="h-3.5 w-3.5" /> Fix Available (Agent Required)
                            </span>
                        @endif
                    @endif
                    <form method="POST" action="{{ route('findings.mark-fixed', $f) }}">@csrf
                        <x-button type="submit" variant="secondary" size="sm" icon="check">Mark as Fixed</x-button>
                    </form>
                    @if ($f->engine === 'rkhunter')
                        {{-- rkhunter: dismiss modal offers "add to baseline". --}}
                        <x-button type="button" variant="secondary" size="sm" icon="x"
                            x-on:click="$dispatch('open-modal', 'dismiss-{{ $f->id }}')">Dismiss / False Positive</x-button>
                        <x-modal name="dismiss-{{ $f->id }}" title="Dismiss Finding" icon="info" maxWidth="max-w-md">
                            <form method="POST" action="{{ route('findings.dismiss', $f) }}">@csrf
                                <p class="text-sm text-slate-600">Mark this rkhunter finding as a false positive. Optionally add it to the rkhunter baseline so it stops recurring on future scans.</p>
                                <div class="mt-4">
                                    <x-toggle name="add_to_baseline" :checked="true" label="Add to rkhunter Baseline"
                                        description="Runs rkhunter --propupd on the Server so this stops re-flagging." />
                                </div>
                                <div class="mt-4">
                                    <x-field label="Note (Optional)" for="note-{{ $f->id }}">
                                        <x-input id="note-{{ $f->id }}" name="note" placeholder="Why this is a false positive" />
                                    </x-field>
                                </div>
                                <div class="mt-5 flex items-center justify-end gap-2">
                                    <x-button type="button" variant="secondary" size="sm" x-on:click="$dispatch('close-modal', 'dismiss-{{ $f->id }}')">Cancel</x-button>
                                    <x-button type="submit" size="sm" icon="x">Dismiss</x-button>
                                </div>
                            </form>
                        </x-modal>
                    @else
                        <form method="POST" action="{{ route('findings.dismiss', $f) }}">@csrf
                            <x-button type="submit" variant="secondary" size="sm" icon="x">Dismiss / False Positive</x-button>
                        </form>
                    @endif
                @else
                    <form method="POST" action="{{ route('findings.reopen', $f) }}">@csrf
                        <x-button type="submit" variant="ghost" size="sm" icon="refresh">Reopen</x-button>
                    </form>
                @endif

                @if ($f->code)
                    <span class="ml-auto max-w-[16rem] truncate rounded-md bg-slate-100 px-2 py-0.5 font-mono text-xs text-slate-500" title="{{ $f->code }}">{{ $f->code }}</span>
                @endif
            </div>
        </div>
    </div>
</li>
