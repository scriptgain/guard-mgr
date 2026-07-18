@php $selected = old('engines', $job->engineList()); @endphp
<x-layouts.app :title="'Edit ' . $job->name">
    <x-page-header :title="'Edit ' . $job->name" icon="shield" subtitle="Adjust the server, engines, or schedule for this scan job." />

    <form method="POST" action="{{ route('jobs.update', $job) }}" class="mt-2">
        @csrf @method('PUT')
        @if ($errors->any())
            <div class="mb-6"><x-alert type="danger" title="Please Fix the Highlighted Fields">Some fields need attention.</x-alert></div>
        @endif

        <x-card>
            <div class="grid grid-cols-1 sm:grid-cols-2 gap-5">
                <x-field label="Server" for="host_id" required :error="$errors->first('host_id')">
                    <x-select id="host_id" name="host_id">
                        @foreach ($hosts as $h)<option value="{{ $h->id }}" @selected(old('host_id', $job->host_id) == $h->id)>{{ $h->name }} — {{ $h->director?->name }}</option>@endforeach
                    </x-select>
                </x-field>
                <x-field label="Scan Job Name" for="name" required :error="$errors->first('name')">
                    <x-input id="name" name="name" :value="old('name', $job->name)" />
                </x-field>
            </div>

            <div class="mt-6 border-t border-slate-100 pt-5">
                <p class="text-sm font-medium text-slate-700">Scan Engines</p>
                <p class="text-xs text-slate-500 mb-3">Choose which security scanners run on each scan.</p>
                @error('engines')<p class="text-xs text-rose-600 mb-2">{{ $message }}</p>@enderror
                <div class="grid grid-cols-1 sm:grid-cols-3 gap-3">
                    @foreach ($engines as $key => [$label, $desc])
                        <label class="flex flex-col gap-2 rounded-lg border border-slate-200 p-4 hover:border-brand-300 transition">
                            <x-check-switch name="engines[]" :value="$key" :checked="in_array($key, $selected)">{{ $label }}</x-check-switch>
                            <span class="text-xs text-slate-500">{{ $desc }}</span>
                        </label>
                    @endforeach
                </div>
            </div>

            <div class="mt-6 border-t border-slate-100 pt-5" x-data="{ cron: '{{ old('schedule_cron', $job->schedule_cron) }}' }">
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
                    <x-toggle name="enabled" :checked="old('enabled', $job->enabled)" label="Enabled" description="Run this scan job on its schedule." />
                </div>
            </div>

            <x-slot:footer>
                <div class="flex items-center justify-end gap-2">
                    <x-button variant="secondary" href="{{ route('jobs.show', $job) }}">Cancel</x-button>
                    <x-button type="submit" icon="check">Save Changes</x-button>
                </div>
            </x-slot:footer>
        </x-card>
    </form>
</x-layouts.app>
