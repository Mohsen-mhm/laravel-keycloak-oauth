<?php

namespace MohsenMhm\LaravelKeycloakOauth\Services;

use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use RuntimeException;

class KeycloakService
{
    public function findOrCreateUser($keycloakUser)
    {
        $userModel = config('keycloak-oauth.user_model');

        $user = $userModel::query()->where('keycloak_id', $keycloakUser->getId())->first();

        if (!$user) {
            $user = $userModel::query()->where('email', $keycloakUser->getEmail())->first();
        }

        if ($user) {
            $user->update([
                'keycloak_id' => $keycloakUser->getId(),
                'keycloak_username' => $keycloakUser->getNickname() ?? $keycloakUser->getName(),
                'keycloak_access_token' => $keycloakUser->token,
                'keycloak_refresh_token' => $keycloakUser->refreshToken,
                'keycloak_roles' => $this->extractRoles($keycloakUser),
                'keycloak_token_expires_at' => $keycloakUser->expiresIn ? now()->addSeconds($keycloakUser->expiresIn) : null,
            ]);
        } else {
            $fullName = $keycloakUser->getName() ?? '';
            $nameParts = explode(' ', trim($fullName), 2);
            $firstName = $nameParts[0] ?? 'Unknown';
            $lastName = $nameParts[1] ?? 'User';

            $user = $userModel::query()->create([
                'first_name' => $firstName,
                'last_name' => $lastName,
                'email' => $keycloakUser->getEmail(),
                'keycloak_id' => $keycloakUser->getId(),
                'keycloak_username' => $keycloakUser->getNickname() ?? $keycloakUser->getName(),
                'keycloak_access_token' => $keycloakUser->token,
                'keycloak_refresh_token' => $keycloakUser->refreshToken,
                'keycloak_roles' => $this->extractRoles($keycloakUser),
                'password' => Hash::make($keycloakUser->getId()),
                'keycloak_token_expires_at' => $keycloakUser->expiresIn ? now()->addSeconds($keycloakUser->expiresIn) : null,
            ]);
        }

        return $user;
    }

    public function extractRoles($keycloakUser): array
    {
        $roles = [];
        $clientId = config('keycloak-oauth.keycloak.client_id');

        try {
            $accessToken = $keycloakUser->token;
            $tokenParts = explode('.', $accessToken);

            if (count($tokenParts) !== 3) {
                Log::warning('Invalid JWT token format');
                return [];
            }

            $payload = json_decode(base64_decode(str_pad(strtr($tokenParts[1], '-_', '+/'), strlen($tokenParts[1]) % 4, '=', STR_PAD_RIGHT)), true);

            if (!$payload) {
                Log::warning('Failed to decode JWT payload');
                return [];
            }

            Log::info('JWT payload', ['payload' => $payload]);

            if (isset($payload['resource_access'][$clientId]['roles'])) {
                $roles = $payload['resource_access'][$clientId]['roles'];
            }

            Log::info('Extracted client-specific roles from JWT', ['roles' => $roles, 'client_id' => $clientId]);

        } catch (\Exception $e) {
            Log::error('Error extracting roles from JWT token', [
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);

            $user = $keycloakUser->user;
            if (isset($user['resource_access'][$clientId]['roles'])) {
                $roles = $user['resource_access'][$clientId]['roles'];
            }
        }

        return array_unique($roles);
    }

    public function getKeycloakLogoutUrl(): string
    {
        $baseUrl = config('keycloak-oauth.keycloak.base_url');
        $realm = config('keycloak-oauth.keycloak.realm');
        $redirectUri = urlencode(config('keycloak-oauth.frontend_url'));

        return "{$baseUrl}/realms/{$realm}/protocol/openid-connect/logout?redirect_uri={$redirectUri}";
    }

    public function refreshKeycloakToken(string $refreshToken): array
    {
        $baseUrl = config('keycloak-oauth.keycloak.base_url');
        $realm = config('keycloak-oauth.keycloak.realm');
        $clientId = config('keycloak-oauth.keycloak.client_id');
        $clientSecret = config('keycloak-oauth.keycloak.client_secret');

        $response = Http::asForm()->post("{$baseUrl}/realms/{$realm}/protocol/openid-connect/token", [
            'grant_type' => 'refresh_token',
            'refresh_token' => $refreshToken,
            'client_id' => $clientId,
            'client_secret' => $clientSecret,
        ]);

        if ($response->failed()) {
            throw new RuntimeException('Failed to refresh token: ' . $response->body());
        }

        return $response->json();
    }

    public function fetchRolesFromKeycloak(string $accessToken): array
    {
        $roles = [];
        $clientId = config('keycloak-oauth.keycloak.client_id');

        try {
            $tokenParts = explode('.', $accessToken);

            if (count($tokenParts) !== 3) {
                throw new \Exception('Invalid JWT token format');
            }

            $payload = json_decode(base64_decode(str_pad(strtr($tokenParts[1], '-_', '+/'), strlen($tokenParts[1]) % 4, '=', STR_PAD_RIGHT)), true);

            if (!$payload) {
                throw new \Exception('Failed to decode JWT payload');
            }

            Log::info('JWT payload for role extraction', [
                'payload' => $payload,
                'client_id' => $clientId,
                'resource_access' => $payload['resource_access'] ?? 'not found'
            ]);

            if (isset($payload['resource_access'][$clientId]['roles'])) {
                $roles = $payload['resource_access'][$clientId]['roles'];
                Log::info('Found client roles', ['roles' => $roles]);
            } else {
                Log::warning('No client roles found', [
                    'client_id' => $clientId,
                    'available_clients' => array_keys($payload['resource_access'] ?? [])
                ]);
            }

        } catch (\Exception $e) {
            Log::error('Error extracting roles from JWT token', [
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }

        return array_unique($roles);
    }
}