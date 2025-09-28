<?php

use Illuminate\Support\Facades\Route;
use MohsenMhm\LaravelKeycloakOauth\Controllers\KeycloakAuthController;

Route::get('/login', [KeycloakAuthController::class, 'redirectToKeycloak']);
Route::get('/callback', [KeycloakAuthController::class, 'handleKeycloakCallback']);

Route::middleware('auth:api')->group(function () {
    Route::post('/logout', [KeycloakAuthController::class, 'logout']);
    Route::post('/refresh', [KeycloakAuthController::class, 'refreshToken']);
    Route::post('/sync-roles', [KeycloakAuthController::class, 'syncRoles']);
    Route::get('/user', [KeycloakAuthController::class, 'user']);
    Route::get('/user/roles', [KeycloakAuthController::class, 'getUserRoles']);
    Route::get('/user/permissions', [KeycloakAuthController::class, 'getUserPermissions']);
    Route::get('/roles', [KeycloakAuthController::class, 'getAllRoles']);
});

Route::get('/health', [KeycloakAuthController::class, 'healthCheck']);