<x-layouts.app title="Add Server">
    <x-page-header title="Add Server" icon="server" :subtitle="'Director: ' . $director->name" />

    <form method="POST" action="{{ route('hosts.store', $director) }}">
        @csrf

        @if ($errors->any())
            <div class="mb-6"><x-alert type="danger" title="Please fix the highlighted fields">Some fields need attention.</x-alert></div>
        @endif

        <x-card>
            <div class="mb-5 rounded-xl border border-brand-200 bg-brand-50/60 p-4 text-sm text-slate-600">
                GuardMGR scans a server by running the <strong>agent</strong> on it. Add the server here, then open its page and run the one-line install command to enroll the agent &mdash; it dials out to the Manager (no inbound ports) and runs its scan jobs.
            </div>

            <div class="grid grid-cols-1 sm:grid-cols-2 gap-5">
                <x-field label="Server Name" for="name" required :error="$errors->first('name')">
                    <x-input id="name" name="name" :value="old('name')" required autofocus placeholder="e.g. web-prod-01" />
                </x-field>

                <x-field label="Default Schedule" for="default_schedule_template_id" hint="Prefills new scan jobs on this server." :error="$errors->first('default_schedule_template_id')">
                    <x-select id="default_schedule_template_id" name="default_schedule_template_id">
                        <option value="">No default</option>
                        @foreach ($scheduleTemplates as $tpl)
                            <option value="{{ $tpl->id }}" @selected(old('default_schedule_template_id') == $tpl->id)>{{ $tpl->name }}</option>
                        @endforeach
                    </x-select>
                </x-field>

                @if ($owners->isNotEmpty())
                    <x-field label="Owner" for="owner_id" hint="Which user this server belongs to." :error="$errors->first('owner_id')">
                        <x-select id="owner_id" name="owner_id">
                            <option value="">Director's owner</option>
                            @foreach ($owners as $o)
                                <option value="{{ $o->id }}" @selected(old('owner_id') == $o->id)>{{ $o->name }} ({{ $o->email }})</option>
                            @endforeach
                        </x-select>
                    </x-field>
                @endif

                <x-field label="Notes" for="notes" class="sm:col-span-2" :error="$errors->first('notes')">
                    <textarea id="notes" name="notes" rows="2" class="block w-full rounded-lg border-0 px-3 py-2 text-sm text-slate-900 ring-1 ring-inset ring-slate-300 focus:ring-2 focus:ring-inset focus:ring-brand-500">{{ old('notes') }}</textarea>
                </x-field>
            </div>

            <x-slot:footer>
                <div class="flex items-center justify-end gap-2 w-full">
                    <x-button variant="secondary" href="{{ route('directors.show', $director) }}">Cancel</x-button>
                    <x-button type="submit" icon="plus">Add Server</x-button>
                </div>
            </x-slot:footer>
        </x-card>
    </form>
</x-layouts.app>
