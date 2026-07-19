<?php

// Branding. Rename the whole product from one place. These defaults can be
// overridden by env, and by DB settings applied at boot (the Branding settings
// screen) — matching the DB-driven config pattern.
return [
    'name' => env('BRAND_NAME', env('APP_NAME', 'GuardMGR')),
    'tagline' => env('BRAND_TAGLINE', 'Server Security Scanning'),
    // Accent hex; overrides the amber brand ramp at runtime. Settable in the UI.
    // Amber keeps red/rose free for severity + failure states.
    'accent' => env('BRAND_ACCENT', '#ea580c'),
    // Logo/favicon glyph (an x-icon name). Distinct per product.
    'icon' => env('BRAND_ICON', 'shield'),
];
