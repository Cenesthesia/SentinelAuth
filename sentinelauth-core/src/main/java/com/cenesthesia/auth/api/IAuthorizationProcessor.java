package com.cenesthesia.auth.api;

import com.cenesthesia.auth.common.AuthPrincipal;
import com.cenesthesia.auth.common.AuthResult;

import java.util.Collection;

/**
 * Интерфейс для сервисов отвечающих за авторизацию
 *
 * @author Cenesthesia
 * @version 1.0
 */
public interface IAuthorizationProcessor {
    /**
     * Проверяет наличие роли у пользователя
     * @see IAuthorizationProcessor#hasAllRoles(AuthPrincipal, Collection)
     * @see IAuthorizationProcessor#hasAnyRole(AuthPrincipal, Collection)
     * @see IAuthorizationProcessor#hasAnyRoles(AuthPrincipal, Collection, int)
     * @see IAuthorizationProcessor#hasRoleWithContext(AuthPrincipal, String, Object)
     * @see AuthResult
     *
     * @param principal пользовательская информация
     * @param role проверяемая роль
     * @return успешность авторизации {@link AuthResult}
     */
    AuthResult hasRole(AuthPrincipal principal, String role);

    /**
     * Проверяет наличие нескольких ролей у пользователя
     * @see IAuthorizationProcessor#hasRole(AuthPrincipal, String)
     * @see IAuthorizationProcessor#hasAnyRole(AuthPrincipal, Collection)
     * @see IAuthorizationProcessor#hasAnyRoles(AuthPrincipal, Collection, int)
     * @see IAuthorizationProcessor#hasRoleWithContext(AuthPrincipal, String, Object)
     * @see AuthResult
     *
     * @param principal пользовательская информация
     * @param roles проверяемые роли
     * @return успешность авторизации {@link AuthResult}
     */
    AuthResult hasAllRoles(AuthPrincipal principal, Collection<String> roles);

    /**
     * Проверяет наличие хотя бы одной роли из {@code roles} у пользователя
     * @see IAuthorizationProcessor#hasRole(AuthPrincipal, String)
     * @see IAuthorizationProcessor#hasAllRoles(AuthPrincipal, Collection)
     * @see IAuthorizationProcessor#hasAnyRoles(AuthPrincipal, Collection, int)
     * @see IAuthorizationProcessor#hasRoleWithContext(AuthPrincipal, String, Object)
     * @see AuthResult
     *
     * @param principal пользовательская информация
     * @param roles проверяемые роли
     * @return успешность авторизации {@link AuthResult}
     */
    AuthResult hasAnyRole(AuthPrincipal principal, Collection<String> roles);

    /**
     * Проверяет наличие хотя бы {@code count} ролей у пользователя
     * @see IAuthorizationProcessor#hasRole(AuthPrincipal, String)
     * @see IAuthorizationProcessor#hasAllRoles(AuthPrincipal, Collection)
     * @see IAuthorizationProcessor#hasAnyRole(AuthPrincipal, Collection)
     * @see IAuthorizationProcessor#hasRoleWithContext(AuthPrincipal, String, Object)
     * @see AuthResult
     *
     * @param principal пользовательская информация
     * @param roles проверяемые роли
     * @param count количество ролей из списка, которыми должен обладать пользователь
     * @return успешность авторизации {@link AuthResult}
     */
    AuthResult hasAnyRoles(AuthPrincipal principal, Collection<String> roles, int count);

    /**
     * Проверяет наличие права у пользователя
     * @see IAuthorizationProcessor#hasAllPermissions(AuthPrincipal, Collection)
     * @see IAuthorizationProcessor#hasAnyPermission(AuthPrincipal, Collection)
     * @see IAuthorizationProcessor#hasAnyPermissions(AuthPrincipal, Collection, int)
     * @see IAuthorizationProcessor#hasRoleWithContext(AuthPrincipal, String, Object)
     * @see AuthResult
     *
     * @param principal пользовательская информация
     * @param permission право на проверку
     * @return успешность авторизации {@link AuthResult}
     */
    AuthResult hasPermission(AuthPrincipal principal, String permission);

    /**
     * Проверяет наличие нескольких прав у пользователя
     * @see IAuthorizationProcessor#hasPermission(AuthPrincipal, String)
     * @see IAuthorizationProcessor#hasAnyPermission(AuthPrincipal, Collection)
     * @see IAuthorizationProcessor#hasAnyPermissions(AuthPrincipal, Collection, int)
     * @see IAuthorizationProcessor#hasPermissionWithContext(AuthPrincipal, String, Object)
     * @see AuthResult
     *
     * @param principal пользовательская информация
     * @param permissions права на проверку
     * @return успешность авторизации {@link AuthResult}
     */
    AuthResult hasAllPermissions(AuthPrincipal principal, Collection<String> permissions);

    /**
     * Проверяет наличие хотя бы одного права из {@code permissions} у пользователя
     * @see IAuthorizationProcessor#hasPermission(AuthPrincipal, String)
     * @see IAuthorizationProcessor#hasAllPermissions(AuthPrincipal, Collection)
     * @see IAuthorizationProcessor#hasAnyPermissions(AuthPrincipal, Collection, int)
     * @see IAuthorizationProcessor#hasPermissionWithContext(AuthPrincipal, String, Object)
     * @see AuthResult
     *
     * @param principal пользовательская информация
     * @param permissions права на проверку
     * @return успешность авторизации {@link AuthResult}
     */
    AuthResult hasAnyPermission(AuthPrincipal principal, Collection<String> permissions);

    /**
     * Проверяет наличие хотя бы {@code count} прав у пользователя из
     * {@code permissions}
     * @see IAuthorizationProcessor#hasPermission(AuthPrincipal, String)
     * @see IAuthorizationProcessor#hasAllPermissions(AuthPrincipal, Collection)
     * @see IAuthorizationProcessor#hasAnyPermission(AuthPrincipal, Collection)
     * @see IAuthorizationProcessor#hasPermissionWithContext(AuthPrincipal, String, Object)
     * @see AuthResult
     *
     * @param principal пользовательская информация
     * @param permissions права на проверку
     * @param count количество прав из списка, которыми должен обладать пользователь
     * @return успешность авторизации {@link AuthResult}
     */
    AuthResult hasAnyPermissions(AuthPrincipal principal, Collection<String> permissions, int count);

    /**
     * Проверяет наличие у пользователя роли с дополнительной контекстной информацией.
     * Заделка для кастомных авторизационных сервисов. По умолчанию функционал аналогичен
     * {@link IAuthorizationProcessor#hasRole(AuthPrincipal, String)}
     * @see IAuthorizationProcessor#hasRole(AuthPrincipal, String)
     * @see IAuthorizationProcessor#hasAllRoles(AuthPrincipal, Collection)
     * @see IAuthorizationProcessor#hasAnyRole(AuthPrincipal, Collection)
     * @see IAuthorizationProcessor#hasAnyRoles(AuthPrincipal, Collection, int)
     * @see AuthResult
     *
     * @param principal пользовательская информация
     * @param role проверяемая роль
     * @param context контекст
     * @return успешность авторизации {@link AuthResult}
     */
    default AuthResult hasRoleWithContext(AuthPrincipal principal, String role, Object context) {
        return hasRole(principal, role);
    }

    /**
     * Проверяет наличие права у пользователя с дополнительной контекстной информацией.
     * Заделка для кастомных авторизационных сервисов. По умолчанию функционал аналогичен
     * {@link IAuthorizationProcessor#hasPermission(AuthPrincipal, String)}
     * @see IAuthorizationProcessor#hasPermission(AuthPrincipal, String)
     * @see IAuthorizationProcessor#hasAllPermissions(AuthPrincipal, Collection)
     * @see IAuthorizationProcessor#hasAnyPermission(AuthPrincipal, Collection)
     * @see IAuthorizationProcessor#hasAnyPermissions(AuthPrincipal, Collection, int)
     * @see AuthResult
     *
     * @param principal пользовательская информация
     * @param permission право на проверку
     * @param context контекст
     * @return успешность авторизации {@link AuthResult}
     */
    default AuthResult hasPermissionWithContext(AuthPrincipal principal, String permission, Object context) {
        return hasPermission(principal, permission);
    }
}
