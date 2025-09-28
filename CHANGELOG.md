# Changelog

All notable changes to `laravel-keycloak-oauth` will be documented in this file.

## [1.0.0] - 2024-01-01

### Added
- Initial release
- Keycloak OAuth2 integration using Laravel Socialite
- JWT token parsing for role extraction
- Automatic user creation and synchronization
- Role-based authorization with Laravel Gates
- Token refresh functionality
- User permission management
- Health check endpoints
- Comprehensive documentation
- Migration for adding Keycloak fields to users table
- HasKeycloakAuth trait for User models
- KeycloakService for handling authentication logic
- Configurable routes and middleware
- Support for Laravel 11+ and PHP 8.2+