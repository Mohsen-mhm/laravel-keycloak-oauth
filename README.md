# Laravel Keycloak OAuth

A Laravel package for Keycloak OAuth2 authentication with JWT role extraction and user synchronization.

## Features

- 🔐 Keycloak OAuth2 integration using Laravel Socialite
- 🔍 JWT token parsing for role extraction
- 👤 Automatic user creation and synchronization
- 🛡️ Role-based authorization with Laravel Gates
- 🔄 Token refresh functionality
- 📋 User permission management
- ✅ Health check endpoints
- 🚀 Easy to integrate and configure

## Requirements

- PHP 8.1+
- Laravel 9.0+ (supports Laravel 9, 10, 11, and 12)
- Laravel Passport
- Laravel Socialite
- SocialiteProviders Keycloak

## Installation

Install the package via Composer:

```bash
composer require mohsen-mhm/laravel-keycloak-oauth
```

The package will automatically install the required dependencies including SocialiteProviders Keycloak.

Install Laravel Passport if not already installed:

```bash
# For Laravel 11+
composer require laravel/passport:^12.0
php artisan passport:install

# For Laravel 9-10
composer require laravel/passport:^11.0
php artisan passport:install
```

Publish the configuration file:

```bash
php artisan vendor:publish --tag=keycloak-oauth-config
```

Publish and run the migrations:

```bash
php artisan vendor:publish --tag=keycloak-oauth-migrations
php artisan migrate
```

## Configuration

### Environment Variables

Add the following environment variables to your `.env` file:

```env
KEYCLOAK_CLIENT_ID=your-client-id
KEYCLOAK_CLIENT_SECRET=your-client-secret
KEYCLOAK_REDIRECT_URI=http://localhost:8000/api/auth/keycloak/callback
KEYCLOAK_BASE_URL=http://localhost:8080
KEYCLOAK_REALM=your-realm
FRONTEND_URL=http://localhost:3000
```

### User Model Setup

Add the Keycloak authentication trait to your User model:

```php
<?php

namespace App\Models;

use Illuminate\Foundation\Auth\User as Authenticatable;
use Laravel\Passport\HasApiTokens;
use MohsenMhm\LaravelKeycloakOauth\Traits\HasKeycloakAuth;

class User extends Authenticatable
{
    use HasApiTokens, HasKeycloakAuth;

    protected $fillable = [
        'first_name',
        'last_name',
        'email',
        'password',
        'keycloak_id',
        'keycloak_username',
        'keycloak_roles',
        'keycloak_access_token',
        'keycloak_refresh_token',
        'keycloak_token_expires_at',
    ];

    protected $hidden = [
        'password',
        'keycloak_access_token',
        'keycloak_refresh_token',
    ];

    protected $casts = [
        'keycloak_roles' => 'array',
        'keycloak_token_expires_at' => 'datetime',
    ];
}
```

### Keycloak Client Configuration

In your Keycloak admin console:

1. Create a new client or configure an existing one
2. Set the client protocol to `openid-connect`
3. Set the access type to `confidential`
4. Add your redirect URI: `http://localhost:8000/api/auth/keycloak/callback`
5. Enable the following standard flows:
   - Standard Flow Enabled
   - Direct Access Grants Enabled
6. Configure client roles as needed

## Usage

### API Endpoints

The package automatically registers the following routes:

#### Authentication Routes
- `GET /api/auth/keycloak/login` - Get Keycloak login URL
- `GET /api/auth/keycloak/callback` - Handle OAuth callback
- `POST /api/auth/keycloak/logout` - Logout user (requires authentication)
- `POST /api/auth/keycloak/refresh` - Refresh tokens (requires authentication)
- `POST /api/auth/keycloak/sync-roles` - Sync user roles (requires authentication)

#### User Management Routes
- `GET /api/auth/keycloak/user` - Get current user (requires authentication)
- `GET /api/auth/keycloak/user/roles` - Get user roles (requires authentication)
- `GET /api/auth/keycloak/user/permissions` - Get user permissions (requires authentication)
- `GET /api/auth/keycloak/roles` - Get all available roles (requires authentication)

#### Health Check
- `GET /api/auth/keycloak/health` - Application health check

### Frontend Integration

#### Step 1: Get Login URL
```javascript
const response = await fetch('/api/auth/keycloak/login');
const data = await response.json();
window.location.href = data.data.auth_url;
```

#### Step 2: Handle Callback
After successful authentication, users will be redirected to your frontend URL with a token:
```
http://localhost:3000/auth?token=YOUR_ACCESS_TOKEN&user_id=123
```

#### Step 3: Use the Token
Include the token in your API requests:
```javascript
const response = await fetch('/api/auth/keycloak/user', {
    headers: {
        'Authorization': `Bearer ${token}`,
        'Accept': 'application/json'
    }
});
```

### Role Management

#### Defining Roles
Configure your application roles in `config/keycloak-oauth.php`:

```php
'default_roles' => [
    'god',
    'admin',
    'user',
    'currencies.index',
    'currencies.create',
    'currencies.edit',
    'currencies.delete',
    // Add more roles as needed
],
```

#### Using Roles in Controllers

```php
<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Gate;

class CurrencyController extends Controller
{
    public function index(Request $request)
    {
        Gate::authorize('currencies.index');

        // Your logic here
    }

    public function store(Request $request)
    {
        Gate::authorize('currencies.create');

        // Your logic here
    }
}
```

#### Using Roles in Middleware

```php
Route::middleware(['auth:api', 'can:currencies.index'])->group(function () {
    Route::get('/currencies', [CurrencyController::class, 'index']);
});
```

#### Using Roles in Views/Frontend

```php
// Check if user has specific role
if ($user->hasRole('admin')) {
    // Show admin content
}

// Check if user has any of the specified roles
if ($user->hasAnyRole(['admin', 'moderator'])) {
    // Show content for admin or moderator
}

// Check using Gates
if (Gate::allows('currencies.create')) {
    // Show create button
}
```

### Token Management

#### Check Token Expiration
```php
if ($user->isKeycloakTokenExpired()) {
    // Refresh token or re-authenticate
}
```

#### Refresh Token
```javascript
const response = await fetch('/api/auth/keycloak/refresh', {
    method: 'POST',
    headers: {
        'Authorization': `Bearer ${currentToken}`,
        'Accept': 'application/json'
    }
});

if (response.ok) {
    const data = await response.json();
    const newToken = data.data.access_token;
    // Update stored token
}
```

## Configuration Options

The package provides several configuration options in `config/keycloak-oauth.php`:

```php
return [
    'keycloak' => [
        'client_id' => env('KEYCLOAK_CLIENT_ID'),
        'client_secret' => env('KEYCLOAK_CLIENT_SECRET'),
        'redirect' => env('KEYCLOAK_REDIRECT_URI'),
        'base_url' => env('KEYCLOAK_BASE_URL'),
        'realm' => env('KEYCLOAK_REALM'),
    ],

    'frontend_url' => env('FRONTEND_URL', env('APP_URL')),

    'default_roles' => [
        // Define your application roles here
    ],

    'routes' => [
        'enabled' => true,
        'prefix' => 'api/auth/keycloak',
        'middleware' => ['api'],
    ],

    'user_model' => env('KEYCLOAK_USER_MODEL', App\Models\User::class),
];
```

## Error Handling

The package provides consistent error responses:

```json
{
    "success": false,
    "message": "Error message here",
    "data": {
        "error": "Detailed error information"
    }
}
```

Common error scenarios:
- Invalid or expired tokens
- Missing Keycloak configuration
- Network issues with Keycloak server
- Invalid user permissions

## Testing

You can disable routes in testing by setting the configuration:

```php
// In your test setup
config(['keycloak-oauth.routes.enabled' => false]);
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Security

If you discover any security related issues, please email mohsen.mhm@example.com instead of using the issue tracker.

## License

The MIT License (MIT). Please see [License File](LICENSE.md) for more information.