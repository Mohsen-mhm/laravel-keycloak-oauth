<?php

namespace MohsenMhm\LaravelKeycloakOauth\Controllers;

use Illuminate\Http\Request;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\RedirectResponse;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Laravel\Socialite\Facades\Socialite;
use MohsenMhm\LaravelKeycloakOauth\Services\KeycloakService;
use RuntimeException;

class KeycloakAuthController extends Controller
{
    protected KeycloakService $keycloakService;

    public function __construct(KeycloakService $keycloakService)
    {
        $this->keycloakService = $keycloakService;
    }

    public function redirectToKeycloak(Request $request): JsonResponse
    {
        $authUrl = Socialite::driver('keycloak')
            ->scopes(['openid', 'profile', 'email'])
            ->redirect()->getTargetUrl();

        return response()->json([
            'success' => true,
            'message' => 'Login URL generated successfully',
            'data' => [
                'auth_url' => $authUrl,
            ]
        ], 200);
    }

    public function handleKeycloakCallback(Request $request): RedirectResponse
    {
        try {
            Log::info('Keycloak callback received', [
                'code' => $request->get('code'),
                'all_params' => $request->all()
            ]);

            $keycloakUser = Socialite::driver('keycloak')->stateless()->user();
            $user = $this->keycloakService->findOrCreateUser($keycloakUser);
            $token = $user->createToken('Keycloak API Token')->accessToken;

            $frontendUrl = config('keycloak-oauth.frontend_url');
            $redirectUrl = $frontendUrl . '/auth?token=' . urlencode($token) . '&user_id=' . $user->id;

            Log::info('Redirecting to frontend after successful authentication', [
                'user_id' => $user->id,
                'redirect_url' => $redirectUrl
            ]);

            return redirect($redirectUrl);

        } catch (\Exception $e) {
            Log::error(__CLASS__ . ":" . __FUNCTION__ . ":" . __LINE__, [
                'exception' => $e,
                'request_params' => $request->all(),
            ]);

            $frontendUrl = config('keycloak-oauth.frontend_url');
            $errorUrl = $frontendUrl . '/auth?message=' . urlencode($e->getMessage());

            return redirect($errorUrl);
        }
    }

    public function user(Request $request): JsonResponse
    {
        return response()->json([
            'success' => true,
            'message' => 'User retrieved successfully',
            'data' => [
                'user' => $request->user()
            ]
        ]);
    }

    public function logout(Request $request): JsonResponse
    {
        $user = $request->user();

        if ($user) {
            $user->tokens()->delete();

            $logoutUrl = $this->keycloakService->getKeycloakLogoutUrl();

            return response()->json([
                'success' => true,
                'message' => 'Logout successful',
                'data' => [
                    'keycloak_logout_url' => $logoutUrl
                ]
            ]);
        }

        return response()->json([
            'success' => false,
            'message' => 'No authenticated user found'
        ], 401);
    }

    public function refreshToken(Request $request): JsonResponse
    {
        $user = $request->user();

        if (!$user || !$user->keycloak_refresh_token) {
            return response()->json([
                'success' => false,
                'message' => 'No refresh token available'
            ], 401);
        }

        try {
            $refreshedTokens = $this->keycloakService->refreshKeycloakToken($user->keycloak_refresh_token);

            $user->update([
                'keycloak_access_token' => $refreshedTokens['access_token'],
                'keycloak_refresh_token' => $refreshedTokens['refresh_token'] ?? $user->keycloak_refresh_token,
                'keycloak_token_expires_at' => now()->addSeconds($refreshedTokens['expires_in'])
            ]);

            return response()->json([
                'success' => true,
                'message' => 'Token refreshed successfully',
                'data' => [
                    'access_token' => $refreshedTokens['access_token'],
                    'expires_in' => $refreshedTokens['expires_in']
                ]
            ]);

        } catch (\Exception $e) {
            return response()->json([
                'success' => false,
                'message' => 'Failed to refresh token',
                'data' => [
                    'error' => $e->getMessage()
                ]
            ], 401);
        }
    }

    public function getUserRoles(Request $request): JsonResponse
    {
        return response()->json([
            'success' => true,
            'message' => 'User roles retrieved successfully',
            'data' => [
                'roles' => $request->user()->keycloak_roles ?? []
            ]
        ]);
    }

    public function getAllRoles(): JsonResponse
    {
        $roles = config('keycloak-oauth.default_roles', []);

        return response()->json([
            'success' => true,
            'message' => 'Roles retrieved successfully',
            'data' => [
                'roles' => $roles,
                'total_roles' => count($roles)
            ]
        ]);
    }

    public function getUserPermissions(Request $request): JsonResponse
    {
        $user = $request->user();
        $roles = config('keycloak-oauth.default_roles', []);

        $permissions = [];
        $resourcePermissions = [];

        foreach ($roles as $role) {
            $permissions[$role] = Gate::allows($role);
        }

        $resources = [
            'currencies',
            'accounts',
            'exchanges',
            'pairs',
            'exchange.pairs',
            'destination.orders',
            'source.orders',
            'wallets',
            'systems.logs',
            'users'
        ];

        $actions = ['index', 'create', 'edit', 'delete', 'show'];

        foreach ($resources as $resource) {
            $resourcePermissions[$resource] = [];

            foreach ($actions as $action) {
                $permission = "$resource.$action";
                if (in_array($permission, $roles, true)) {
                    $resourcePermissions[$resource][$action] = Gate::allows($permission);
                }
            }
        }

        return response()->json([
            'success' => true,
            'message' => 'User permissions retrieved successfully',
            'data' => [
                'user_roles' => $user->keycloak_roles ?? [],
                'is_super_admin' => Gate::allows('god'),
                'permissions' => $permissions,
                'resource_permissions' => $resourcePermissions
            ]
        ]);
    }

    public function syncRoles(Request $request): JsonResponse
    {
        $user = $request->user();

        if (!$user || !$user->keycloak_access_token) {
            return response()->json([
                'success' => false,
                'message' => 'No access token available'
            ], 401);
        }

        try {
            $freshRoles = $this->keycloakService->fetchRolesFromKeycloak($user->keycloak_access_token);

            $oldRoles = $user->keycloak_roles ?? [];
            $user->update(['keycloak_roles' => $freshRoles]);

            $rolesChanged = $oldRoles !== $freshRoles;

            return response()->json([
                'success' => true,
                'message' => 'Roles synced successfully',
                'data' => [
                    'roles' => $freshRoles,
                    'updated' => $rolesChanged,
                    'previous_roles' => $oldRoles
                ]
            ]);

        } catch (\Exception $e) {
            Log::error('Failed to sync roles from Keycloak', [
                'user_id' => $user->id,
                'error' => $e->getMessage()
            ]);

            return response()->json([
                'success' => false,
                'message' => 'Failed to sync roles',
                'data' => [
                    'error' => $e->getMessage()
                ]
            ], 401);
        }
    }

    public function healthCheck(): JsonResponse
    {
        return response()->json([
            'success' => true,
            'message' => 'Application is healthy',
            'data' => [
                'status' => 'OK',
                'timestamp' => now(),
                'keycloak_configured' => config('keycloak-oauth.keycloak.client_id') ? true : false
            ]
        ]);
    }
}