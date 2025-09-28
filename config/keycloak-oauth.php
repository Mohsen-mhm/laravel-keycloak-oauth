<?php

return [
    'keycloak' => [
        'client_id' => env('KEYCLOAK_CLIENT_ID'),
        'client_secret' => env('KEYCLOAK_CLIENT_SECRET'),
        'redirect' => env('KEYCLOAK_REDIRECT_URI', '/api/auth/keycloak/callback'),
        'base_url' => env('KEYCLOAK_BASE_URL'),
        'realm' => env('KEYCLOAK_REALM'),
    ],

    'frontend_url' => env('FRONTEND_URL', env('APP_URL')),

    'default_roles' => [
        'god',
        // keycloak roles here
    ],

    'routes' => [
        'enabled' => true,
        'prefix' => 'api/auth/keycloak',
        'middleware' => ['api'],
    ],

    'user_model' => env('KEYCLOAK_USER_MODEL', App\Models\User::class),
];