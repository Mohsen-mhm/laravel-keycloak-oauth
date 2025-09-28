<?php

namespace MohsenMhm\LaravelKeycloakOauth;

use Illuminate\Support\ServiceProvider;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Facades\Route;
use Laravel\Socialite\Facades\Socialite;
use SocialiteProviders\Keycloak\Provider;
use MohsenMhm\LaravelKeycloakOauth\Services\KeycloakService;

class KeycloakOauthServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(
            __DIR__.'/../config/keycloak-oauth.php', 'keycloak-oauth'
        );

        $this->app->singleton(KeycloakService::class, function ($app) {
            return new KeycloakService();
        });
    }

    public function boot(): void
    {
        $this->bootKeycloakSocialite();
        $this->bootGates();
        $this->bootRoutes();
        $this->bootPublishing();
    }

    protected function bootKeycloakSocialite(): void
    {
        $socialite = $this->app->make('Laravel\Socialite\Contracts\Factory');
        $socialite->extend('keycloak', function ($app) use ($socialite) {
            $config = config('keycloak-oauth.keycloak');
            return $socialite->buildProvider(Provider::class, $config);
        });
    }

    protected function bootGates(): void
    {
        $roles = config('keycloak-oauth.default_roles', []);

        foreach ($roles as $role) {
            Gate::define($role, function ($user) use ($role) {
                if ($role === 'god') {
                    return $user->hasRole('god');
                }

                return $user->hasRole('god') || $user->hasRole($role);
            });
        }
    }

    protected function bootRoutes(): void
    {
        if (config('keycloak-oauth.routes.enabled', true)) {
            $this->loadRoutes();
        }
    }

    protected function loadRoutes(): void
    {
        Route::group([
            'prefix' => config('keycloak-oauth.routes.prefix', 'api/auth/keycloak'),
            'middleware' => config('keycloak-oauth.routes.middleware', ['api']),
        ], function () {
            $this->loadRoutesFrom(__DIR__.'/../routes/api.php');
        });
    }

    protected function bootPublishing(): void
    {
        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__.'/../config/keycloak-oauth.php' => config_path('keycloak-oauth.php'),
            ], 'keycloak-oauth-config');

            $this->publishes([
                __DIR__.'/../database/migrations' => database_path('migrations'),
            ], 'keycloak-oauth-migrations');
        }
    }
}