package com.cenesthesia.auth.core;

import com.cenesthesia.auth.api.IAuthorizationProcessor;
import com.cenesthesia.auth.common.AuthPrincipal;
import com.cenesthesia.auth.common.AuthResult;

import java.util.Collection;

//TODO: Существует маленький недостаток в виде отсутствия проверки на пустые строки

/**
 * Базовый сервис авторизации, который сравнивает множества ролей и прав пользователя
 * с передаваемыми значениями
 *
 * @author Cenesthesia
 * @version 1.0
 */
public class SimpleAuthorizationProcessor implements IAuthorizationProcessor {
    @Override
    public AuthResult hasRole(AuthPrincipal principal, String role) {
        try {
            if (principal == null) {
                return AuthResult.failure("Authentication principal cannot be null");
            }

            if (principal.getRoles() == null) {
                return AuthResult.failure("User roles are not defined");
            }

            if (role == null) {
                return AuthResult.failure("Role cannot be null");
            }

            if (role.trim().isEmpty()) {
                return AuthResult.failure("Role cannot be empty");
            }

            boolean hasRole = principal.getRoles().contains(role);
            return hasRole ? AuthResult.success("User has required role: " + role) :
                    AuthResult.failure("User does not have required role: " + role);
        } catch (Exception e) {
            return AuthResult.failure("Unexpected error during role check", e);
        }
    }


    @Override
    public AuthResult hasAllRoles(AuthPrincipal principal, Collection<String> roles) {
        try {
            if (principal == null) {
                return AuthResult.failure("Authentication principal cannot be null");
            }

            if (principal.getRoles() == null) {
                return AuthResult.failure("User roles are not defined");
            }

            if (roles == null) {
                return AuthResult.failure("Roles collection cannot be null");
            }

            if (roles.isEmpty()) {
                return AuthResult.failure("Empty roles collection - no roles to check");
            }

            boolean hasAllRoles = principal.getRoles().containsAll(roles);
            return hasAllRoles ? AuthResult.success("User has all required roles") :
                    AuthResult.failure("User does not have all required roles");
        } catch (Exception e) {
            return AuthResult.failure("Unexpected error during all roles check", e);
        }
    }

    @Override
    public AuthResult hasAnyRole(AuthPrincipal principal, Collection<String> roles) {
        try {
            if (principal == null) {
                return AuthResult.failure("Authentication principal cannot be null");
            }

            if (principal.getRoles() == null) {
                return AuthResult.failure("User roles are not defined");
            }

            if (roles == null) {
                return AuthResult.failure("Roles collection cannot be null");
            }

            if (roles.isEmpty()) {
                return AuthResult.failure("Roles collection is empty");
            }

            boolean hasAnyRole = roles.stream().anyMatch(principal.getRoles()::contains);
            return hasAnyRole ? AuthResult.success("User has at least one required role") :
                    AuthResult.failure("User does not have any of the required roles");
        } catch (Exception e) {
            return AuthResult.failure("Unexpected error during any role check", e);
        }
    }

    @Override
    public AuthResult hasAnyRoles(AuthPrincipal principal, Collection<String> roles, int count) {
        try {
            if (principal == null) {
                return AuthResult.failure("Authentication principal cannot be null");
            }

            if (principal.getRoles() == null) {
                return AuthResult.failure("User roles are not defined");
            }

            if (roles == null) {
                return AuthResult.failure("Roles collections cannot be null");
            }

            if (count < 0) {
                return AuthResult.failure("Count roles cannot be negative: " + count);
            }

            if (count == 0) {
                return AuthResult.success("Count is zero - no roles required");
            }

            long foundCount = roles.stream().filter(principal.getRoles()::contains).limit(count).count();
            boolean hasEnoughRoles = foundCount >= count;
            return hasEnoughRoles ? AuthResult.success("User has at least " + count + " required roles") :
                    AuthResult.failure("User has only " + foundCount + " of required " + count + " roles");
        } catch (Exception e) {
            return AuthResult.failure("Unexpected error during multiple roles check", e);
        }
    }

    @Override
    public AuthResult hasPermission(AuthPrincipal principal, String permission) {
        try {
            if (principal == null) {
                return AuthResult.failure("Authentication principal cannot be null");
            }

            if (principal.getPermissions() == null) {
                return AuthResult.failure("User permissions are not defined");
            }

            if (permission == null) {
                return AuthResult.failure("Permission cannot be null");
            }

            if (permission.trim().isEmpty()) {
                return AuthResult.failure("Permission cannot be empty");
            }

            boolean hasPermission = principal.getPermissions().contains(permission);
            return hasPermission ? AuthResult.success("User has required permission: " + permission) :
                    AuthResult.failure("User does not have required permission: " + permission);
        } catch (Exception e) {
            return AuthResult.failure("Unexpected error during permission check", e);
        }
    }

    @Override
    public AuthResult hasAllPermissions(AuthPrincipal principal, Collection<String> permissions) {
        try {
            if (principal == null) {
                return AuthResult.failure("Authentication principal cannot be null");
            }

            if (principal.getPermissions() == null) {
                return AuthResult.failure("User permissions are not defined");
            }

            if (permissions == null) {
                return AuthResult.failure("Permissions collection cannot be null");
            }

            if (permissions.isEmpty()) {
                return AuthResult.failure("Empty permissions collection - no permission to check");
            }

            boolean hasAllPermissions = principal.getPermissions().containsAll(permissions);
            return hasAllPermissions ? AuthResult.success("User has all required permissions") :
                    AuthResult.failure("User does not have all required permissions");
        } catch (Exception e) {
            return AuthResult.failure("Unexpected error during all permissions check", e);
        }
    }

    @Override
    public AuthResult hasAnyPermission(AuthPrincipal principal, Collection<String> permissions) {
        try {
            if (principal == null) {
                return AuthResult.failure("Authentication principal cannot be null");
            }

            if (principal.getPermissions() == null) {
                return AuthResult.failure("User permissions are not defined");
            }

            if (permissions == null) {
                return AuthResult.failure("Permissions collection cannot be null");
            }

            if (permissions.isEmpty()) {
                return AuthResult.failure("Permissions collection is empty");
            }

            boolean hasAnyPermission = permissions.stream().anyMatch(principal.getPermissions()::contains);
            return hasAnyPermission ? AuthResult.success("User has at least one required permission") :
                    AuthResult.failure("User does not have any of the required permissions");
        } catch (Exception e) {
            return AuthResult.failure("Unexpected error during any permission check", e);
        }
    }

    @Override
    public AuthResult hasAnyPermissions(AuthPrincipal principal, Collection<String> permissions, int count) {
        try {
            if (principal == null) {
                return AuthResult.failure("Authentication principal cannot be null");
            }

            if (principal.getPermissions() == null) {
                return AuthResult.failure("User permissions are not defined");
            }

            if (permissions == null) {
                return AuthResult.failure("Permissions collections cannot be null");
            }

            if (count < 0) {
                return AuthResult.failure("Count permissions cannot be negative: " + count);
            }

            if (count == 0) {
                return AuthResult.success("Count is zero - no permissions required");
            }

            long foundCount = permissions.stream().filter(principal.getPermissions()::contains).limit(count).count();
            boolean hasEnoughPermissions = foundCount >= count;
            return hasEnoughPermissions ? AuthResult.success("User has at least " + count + " required permissions") :
                    AuthResult.failure("User has only " + foundCount + " of required " + count + " permissions");
        } catch (Exception e) {
            return AuthResult.failure("Unexpected error during multiple permissions check", e);
        }
    }
}
