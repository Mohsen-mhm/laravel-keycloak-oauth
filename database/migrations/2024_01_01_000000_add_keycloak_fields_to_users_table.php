<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        if (Schema::hasTable('users')) {
            Schema::table('users', function (Blueprint $table) {
                if (!Schema::hasColumn('users', 'keycloak_id')) {
                    $table->string('keycloak_id')->nullable()->index();
                }
                if (!Schema::hasColumn('users', 'keycloak_username')) {
                    $table->string('keycloak_username')->nullable();
                }
                if (!Schema::hasColumn('users', 'keycloak_roles')) {
                    $table->json('keycloak_roles')->nullable();
                }
                if (!Schema::hasColumn('users', 'keycloak_access_token')) {
                    $table->text('keycloak_access_token')->nullable();
                }
                if (!Schema::hasColumn('users', 'keycloak_refresh_token')) {
                    $table->text('keycloak_refresh_token')->nullable();
                }
                if (!Schema::hasColumn('users', 'keycloak_token_expires_at')) {
                    $table->timestamp('keycloak_token_expires_at')->nullable();
                }
            });
        }
    }

    public function down(): void
    {
        if (Schema::hasTable('users')) {
            Schema::table('users', function (Blueprint $table) {
                $columns = [
                    'keycloak_id',
                    'keycloak_username',
                    'keycloak_roles',
                    'keycloak_access_token',
                    'keycloak_refresh_token',
                    'keycloak_token_expires_at'
                ];

                foreach ($columns as $column) {
                    if (Schema::hasColumn('users', $column)) {
                        $table->dropColumn($column);
                    }
                }
            });
        }
    }
};