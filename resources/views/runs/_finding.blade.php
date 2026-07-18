{{-- One finding row. Expects: $f (Finding), $lbl (severity label), $hex (severity color). --}}
<li class="px-5 py-4">
    <div class="flex flex-wrap items-start justify-between gap-3">
        <div class="min-w-0 flex-1">
            <div class="flex items-center gap-2">
                <span class="inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 text-xs font-medium ring-1 ring-inset"
                      style="color:{{ $hex }};background-color:{{ $hex }}12;border-color:{{ $hex }}30">
                    <span class="h-1.5 w-1.5 rounded-full" style="background-color:{{ $hex }}"></span>{{ $lbl }}
                </span>
                <p class="font-medium text-slate-900">{{ $f->title }}</p>
            </div>
            @if ($f->detail)<p class="mt-1 text-sm text-slate-600 whitespace-pre-wrap break-words">{{ $f->detail }}</p>@endif
            @if ($f->remediation)
                <p class="mt-2 text-sm text-slate-700"><span class="font-medium text-emerald-700">Remediation:</span> {{ $f->remediation }}</p>
            @endif
        </div>
        @if ($f->code)
            <div class="flex shrink-0 items-center gap-2">
                <span class="max-w-[16rem] truncate rounded-md bg-slate-100 px-2 py-0.5 font-mono text-xs text-slate-500" title="{{ $f->code }}">{{ $f->code }}</span>
            </div>
        @endif
    </div>
</li>
