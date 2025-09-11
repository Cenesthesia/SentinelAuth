package com.cenesthesia.auth.api;

import com.cenesthesia.auth.common.AuthPrincipal;

import java.util.Collection;

/**
 * Интерфейс для сервисов отвечающих за авторизацию
 *
 * @author Cenesthesia
 * @version 1.0
 */
public interface IAuthorizationService {
    /**
     * Проверить наличие роли у пользователя
     * @see IAuthorizationService#hasAllRoles(AuthPrincipal, Collection)
     * @see IAuthorizationService#hasAnyRole(AuthPrincipal, Collection)
     * @see IAuthorizationService#hasAnyRoles(AuthPrincipal, Collection, int)
     *
     * @param principal пользовательская информация
     * @param role проверяемая роль
     * @return true, если у пользователя есть роль {@code role}, иначе false
     */
    boolean hasRole(AuthPrincipal principal, String role);

    /**
     * Проверяет наличие нескольких ролей у пользователя
     * @see IAuthorizationService#hasRole(AuthPrincipal, String)
     * @see IAuthorizationService#hasAnyRole(AuthPrincipal, Collection)
     * @see IAuthorizationService#hasAnyRoles(AuthPrincipal, Collection, int)
     *
     * @param principal пользовательская информация
     * @param roles проверяемые роли
     * @return true, если у пользователя есть все роли из {@code roles}, иначе false
     */
    boolean hasAllRoles(AuthPrincipal principal, Collection<String> roles);

    /**
     * Проверяет наличие хотя бы одной роли из {@code roles} у пользователя
     * @see IAuthorizationService#hasRole(AuthPrincipal, String)
     * @see IAuthorizationService#hasAllRoles(AuthPrincipal, Collection)
     * @see IAuthorizationService#hasAnyRoles(AuthPrincipal, Collection, int)
     *
     * @param principal пользовательская информация
     * @param roles проверяемые роли
     * @return true, если у пользователя есть хотя бы одна из ролей {@code roles}, иначе false
     */
    boolean hasAnyRole(AuthPrincipal principal, Collection<String> roles);

    /**
     * Проверяет наличие хотя бы {@code count} ролей у пользователя
     * @see IAuthorizationService#hasRole(AuthPrincipal, String)
     * @see IAuthorizationService#hasAllRoles(AuthPrincipal, Collection)
     * @see IAuthorizationService#hasAnyRole(AuthPrincipal, Collection)
     *
     * @param principal пользовательская информация
     * @param roles проверяемые роли
     * @param count количество ролей из списка, которыми должен обладать пользователь
     * @return true, если у пользователя есть хотя бы {@code count} ролей из {@code roles}, иначе false
     */
    boolean hasAnyRoles(AuthPrincipal principal, Collection<String> roles, int count);

    /**
     * Проверяет наличие права у пользователя
     * @see IAuthorizationService#hasAllPermissions(AuthPrincipal, Collection)
     * @see IAuthorizationService#hasAnyPermission(AuthPrincipal, Collection)
     * @see IAuthorizationService#hasAnyPermissions(AuthPrincipal, Collection, int)
     *
     * @param principal пользовательская информация
     * @param permission право на проверку
     * @return true, если у пользователя есть данное право, иначе false
     */
    boolean hasPermission(AuthPrincipal principal, String permission);

    /**
     * Проверяет наличие нескольких прав у пользователя
     * @see IAuthorizationService#hasPermission(AuthPrincipal, String)
     * @see IAuthorizationService#hasAnyPermission(AuthPrincipal, Collection)
     * @see IAuthorizationService#hasAnyPermissions(AuthPrincipal, Collection, int)
     *
     * @param principal пользовательская информация
     * @param permissions права на проверку
     * @return true, если у пользователя есть все права из {@code permissions}, иначе false
     */
    boolean hasAllPermissions(AuthPrincipal principal, Collection<String> permissions);

    /**
     * Проверяет наличие хотя бы одного права из {@code permissions} у пользователя
     * @see IAuthorizationService#hasPermission(AuthPrincipal, String)
     * @see IAuthorizationService#hasAllPermissions(AuthPrincipal, Collection)
     * @see IAuthorizationService#hasAnyPermissions(AuthPrincipal, Collection, int)
     *
     * @param principal пользовательская информация
     * @param permissions права на проверку
     * @return true, если у пользователя есть хотя бы одно право из {@code permissions}, иначе false
     */
    boolean hasAnyPermission(AuthPrincipal principal, Collection<String> permissions);

    /**
     * Проверяет наличие хотя бы {@code count} прав у пользователя из
     * {@code permissions}
     * @see IAuthorizationService#hasPermission(AuthPrincipal, String)
     * @see IAuthorizationService#hasAllPermissions(AuthPrincipal, Collection)
     * @see IAuthorizationService#hasAnyPermission(AuthPrincipal, Collection)
     *
     * @param principal пользовательская информация
     * @param permissions права на проверку
     * @param count количество прав из списка, которыми должен обладать пользователь
     * @return true, если у пользователя есть хотя бы {@code count} прав из {@code permissions}
     */
    boolean hasAnyPermissions(AuthPrincipal principal, Collection<String> permissions, int count);

    /**
     * Проверяет наличие у пользователя роли с дополнительной контекстной информацией.
     * Заделка для кастомных авторизационных сервисов.
     * @see IAuthorizationService#hasRole(AuthPrincipal, String)
     *
     * @param principal пользовательская информация
     * @param role проверяемая роль
     * @param context контекст
     * @return true, если у пользователя есть роль {@code role} в рамках контекста, иначе false
     */
    default boolean hasRoleWithContext(AuthPrincipal principal, String role, Object context) {
        return hasRole(principal, role);
    }

    /**
     * Проверяет наличие права у пользователя с дополнительной контекстной информацией.
     * Заделка для кастомных авторизационных сервисов.
     * @see IAuthorizationService#hasPermission(AuthPrincipal, String)
     *
     * @param principal пользовательская информация
     * @param permission право на проверку
     * @param context контекст
     * @return true, если у пользователя есть роль {@code role} в рамках контекста, иначе false
     */
    default boolean hasPermissionWithContext(AuthPrincipal principal, String permission, Object context) {
        return hasPermission(principal, permission);
    }
}
