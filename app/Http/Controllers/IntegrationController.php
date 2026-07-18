<?php

namespace App\Http\Controllers;

use App\Models\Setting;
use App\Services\IntegrationNotifier;
use Illuminate\Http\Request;

class IntegrationController extends Controller
{
    public function edit()
    {
        return view('settings.integrations');
    }

    public function update(Request $request)
    {
        $data = $request->validate([
            'integrations_slack_url' => ['nullable', 'url', 'max:500'],
            'integrations_discord_url' => ['nullable', 'url', 'max:500'],
            'integrations_telegram_token' => ['nullable', 'string', 'max:255'],
            'integrations_telegram_chat_id' => ['nullable', 'string', 'max:64'],
            'integrations_webhook_url' => ['nullable', 'url', 'max:500'],
            'wpscan_api_token' => ['nullable', 'string', 'max:255'],
        ]);

        foreach (IntegrationNotifier::CHANNELS as $ch) {
            Setting::put("integrations_{$ch}_enabled", $request->boolean("integrations_{$ch}_enabled") ? '1' : '0');
        }
        foreach (['integrations_slack_url', 'integrations_discord_url', 'integrations_webhook_url', 'integrations_telegram_chat_id'] as $k) {
            Setting::put($k, $data[$k] ?? '');
        }
        // Telegram token is a secret: keep the stored value when left blank.
        if (! empty($data['integrations_telegram_token'])) {
            Setting::put('integrations_telegram_token', $data['integrations_telegram_token']);
        }
        // WPScan token is a secret: keep the stored value when blank, allow an
        // explicit clear by submitting whitespace.
        if (array_key_exists('wpscan_api_token', $data) && $data['wpscan_api_token'] !== null && $data['wpscan_api_token'] !== '') {
            Setting::put('wpscan_api_token', trim($data['wpscan_api_token']));
        }

        return redirect()->route('settings.integrations.edit')->with('status', 'Integrations saved.');
    }

    public function test(Request $request)
    {
        $channel = (string) $request->input('channel');
        if (! in_array($channel, IntegrationNotifier::CHANNELS, true)) {
            return back()->with('status', 'Unknown channel.');
        }

        $ok = IntegrationNotifier::send(
            $channel,
            '[' . config('brand.name') . '] Test message',
            'Your ' . ucfirst($channel) . ' integration is working.'
        );

        return back()->with('status', $ok
            ? ucfirst($channel) . ' test sent.'
            : ucfirst($channel) . ' test failed. Save the channel settings first, then check the URL or token.');
    }
}
