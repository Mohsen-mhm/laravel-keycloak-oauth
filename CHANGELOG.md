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
- Support for Laravel 9, 10, 11, and 12
- Support for PHP 8.1+
- Broad compatibility with Laravel Passport versions
- Auto-discovery for Laravel packages