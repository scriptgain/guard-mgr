@php $oldEngines = old('engines', ['lynis', 'rkhunter', 'ufw']); @endphp
<x-layouts.app title="New Scan Job">
    <x-page-header title="New Scan Job" icon="shield" subtitle="Pick a server, choose the security engines, and set a schedule." />

    @if ($hosts->isEmpty())
        <x-alert type="warn" title="Add a Server First">
            No servers yet — <a href="{{ route('directors.index') }}" class="underline font-medium">add a server</a> under a Director, then enroll its agent.
        </x-alert>
    @endif

    <form method="POST" action="{{ route('jobs.store') }}" class="mt-2">
        @csrf
        @if ($errors->any())
            <div class="mb-6"><x-alert type="danger" title="Please Fix the Highlighted Fields">Some fields need attention.</x-alert></div>
        @endif

        <x-card>
            <div class="grid grid-cols-1 sm:grid-cols-2 gap-5">
                <x-field label="Server" for="host_id" required :error="$errors->first('host_id')">
                    <x-select id="host_id" name="host_id">
                        <option value="">Select a server…</option>
                        @foreach ($hosts as $h)<option value="{{ $h->id }}" @selected(old('host_id', $selectedHost) == $h->id)>{{ $h->name }} — {{ $h->director?->name }}</option>@endforeach
                    </x-select>
                </x-field>
                <x-field label="Scan Job Name" for="name" required :error="$errors->first('name')">
                    <x-input id="name" name="name" :value="old('name')" placeholder="e.g. Nightly Hardening Audit" />
                </x-field>
            </div>

            <div class="mt-6 border-t border-slate-100 pt-5">
                <p class="text-sm font-medium text-slate-700">Scan Engines</p>
                <p class="text-xs text-slate-500 mb-4">Choose which security scanners run on each scan, grouped by what they check. Missing engines are installed automatically where possible.</p>
                @error('engines')<p class="text-xs text-rose-600 mb-2">{{ $message }}</p>@enderror
                @foreach ($engines as $category => $group)
                    <div class="mb-5">
                        <p class="text-xs font-semibold uppercase tracking-wide text-slate-400 mb-2">{{ $category }}</p>
                        <div class="grid grid-cols-1 sm:grid-cols-3 gap-3">
                            @foreach ($group as $key => [$label, $desc])
                                <label class="flex flex-col gap-2 rounded-lg border border-slate-200 p-4 hover:border-brand-300 transition">
                                    <x-check-switch name="engines[]" :value="$key" :checked="in_array($key, $oldEngines)">{{ $label }}</x-check-switch>
                                    <span class="text-xs text-slate-500">{{ $desc }}</span>
                                </label>
                            @endforeach
                        </div>
                    </div>
                @endforeach
            </div>

            <div class="mt-6 border-t border-slate-100 pt-5" x-data="{ cron: '{{ old('schedule_cron') }}' }">
                <div class="grid grid-cols-1 sm:grid-cols-2 gap-5">
                    <x-field label="Template" for="tmpl" hint="Pick a prebuilt schedule, or set a custom cron.">
                        <x-select id="tmpl" x-on:change="if ($event.target.value) cron = $event.target.value">
                            <option value="">Manual only</option>
                            @foreach ($scheduleTemplates as $st)<option value="{{ $st->cron }}">{{ $st->name }} ({{ $st->cron }})</option>@endforeach
                        </x-select>
                    </x-field>
                    <x-field label="Cron Expression" for="schedule_cron" hint="Blank = manual scans only." :error="$errors->first('schedule_cron')">
                        <x-input id="schedule_cron" name="schedule_cron" x-model="cron" placeholder="0 3 * * *" />
                    </x-field>
                </div>
                <div class="mt-5">
                    <x-toggle name="enabled" :checked="true" label="Enabled" description="Run this scan job on its schedule." />
                </div>
            </div>

            <x-slot:footer>
                <div class="flex items-center justify-end gap-2">
                    <x-button variant="secondary" href="{{ route('jobs.index') }}">Cancel</x-button>
                    <x-button type="submit" icon="plus">Create Scan Job</x-button>
                </div>
            </x-slot:footer>
        </x-card>
    </form>
</x-layouts.app>
