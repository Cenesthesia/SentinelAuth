package com.cenesthesia.auth.core;

import com.cenesthesia.auth.api.IAuthorizationProcessor;
import com.cenesthesia.auth.common.AuthPrincipal;

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
    public boolean hasRole(AuthPrincipal principal, String role) {
        if (principal == null || principal.getRoles() == null || role == null)
            return false;
        return principal.getRoles().contains(role);
    }

    @Override
    public boolean hasAllRoles(AuthPrincipal principal, Collection<String> roles) {
        if (principal == null || principal.getRoles() == null || roles == null)
            return false;
        return principal.getRoles().containsAll(roles);
    }

    @Override
    public boolean hasAnyRole(AuthPrincipal principal, Collection<String> roles) {
        if (principal == null || principal.getRoles() == null || roles == null || roles.isEmpty())
            return false;
        return roles.stream().anyMatch(principal.getRoles()::contains);
    }

    @Override
    public boolean hasAnyRoles(AuthPrincipal principal, Collection<String> roles, int count) {
        if (principal == null || principal.getRoles() == null || roles == null)
            return false;

        if (count < 0)
            throw new IllegalArgumentException("Count roles cannot be negative: " + count);

        if (count == 0)
            return true;

        long foundCount = roles.stream().filter(principal.getRoles()::contains).limit(count).count();
        return foundCount >= count;
    }

    @Override
    public boolean hasPermission(AuthPrincipal principal, String permission) {
        if (principal == null || principal.getPermissions() == null || permission == null)
            return false;
        return principal.getPermissions().contains(permission);
    }

    @Override
    public boolean hasAllPermissions(AuthPrincipal principal, Collection<String> permissions) {
        if (principal == null || principal.getPermissions() == null || permissions == null)
            return false;
        return principal.getPermissions().containsAll(permissions);
    }

    @Override
    public boolean hasAnyPermission(AuthPrincipal principal, Collection<String> permissions) {
        if (principal == null || principal.getPermissions() == null || permissions == null || permissions.isEmpty())
            return false;
        return permissions.stream().anyMatch(principal.getPermissions()::contains);
    }

    @Override
    public boolean hasAnyPermissions(AuthPrincipal principal, Collection<String> permissions, int count) {
        if (principal == null || principal.getPermissions() == null || permissions == null)
            return false;

        if (count < 0)
            throw new IllegalArgumentException("Count permissions cannot be negative: " + count);

        if (count == 0)
            return true;

        long foundCount = permissions.stream().filter(principal.getPermissions()::contains).limit(count).count();
        return foundCount >= count;
    }
}
