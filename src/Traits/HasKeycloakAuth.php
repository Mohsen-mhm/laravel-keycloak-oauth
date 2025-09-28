<?php

namespace MohsenMhm\LaravelKeycloakOauth\Traits;

trait HasKeycloakAuth
{
    public function hasRole(string $role): bool
    {
        return in_array($role, $this->keycloak_roles ?? []);
    }

    public function hasAnyRole(array $roles): bool
    {
        return !empty(array_intersect($roles, $this->keycloak_roles ?? []));
    }

    public function getNameAttribute(): string
    {
        return trim($this->first_name . ' ' . $this->last_name);
    }

    public function isKeycloakTokenExpired(): bool
    {
        if (!$this->keycloak_token_expires_at) {
            return false;
        }

        return $this->keycloak_token_expires_at->isPast();
    }

    public function getKeycloakRolesAttribute($value): array
    {
        return $value ? (is_array($value) ? $value : json_decode($value, true)) : [];
    }

    public function setKeycloakRolesAttribute($value): void
    {
        $this->attributes['keycloak_roles'] = is_array($value) ? json_encode($value) : $value;
    }
}