package com.cenesthesia.auth.api;

import com.cenesthesia.auth.common.Credentials;
import com.cenesthesia.auth.core.AuthenticationResult;

import java.util.Collection;

/**
 * Версия сервиса аутентификации для одно-пользовательских Desktop-приложений
 * !(Нестабильный, в будущем будет заменена или модифицирована)
 *
 * @author Cenesthesia
 * @version 1.0
 */
public interface IAuthenticationService {
    /**
     * Выполнить аутентификацию пользователя
     *
     * @param credentials реквизиты пользователя
     * @return результат аутентификации
     */
    AuthenticationResult authenticate(Credentials credentials);

    /**
     * Завершить сеанс аутентификации пользователя
     *
     * @return true, если сеанс успешно завершен, иначе false
     */
    boolean logout();

    /**
     * Завершить сеанс аутентификации пользователя по его уникальному идентификатору
     * !!(Наработка на будущее)
     *
     * @param id идентификатор сеанса
     * @return true, если сеанс успешно завершен, иначе false
     */
    boolean logout(String id);

    /**
     * Проверить статус аутентификации в системе
     *
     * @return true, если есть аутентифицированный пользователь, иначе false
     */
    boolean verifyAuth();

    /**
     * Проверить наличие роли у аутентифицированного пользователя
     * @see IAuthenticationService#hasAllRoles(Collection)
     * @see IAuthenticationService#hasAnyRoles(Collection)
     * @see IAuthenticationService#hasAnyRoles(Collection, int)
     *
     * @param role проверяемая роль
     * @return true, если у пользователя есть роль {@code role}, иначе false
     */
    boolean hasRole(String role);

    /**
     * Проверить наличие нескольких ролей у аутентифицированного пользователя
     * @see IAuthenticationService#hasRole(String)
     * @see IAuthenticationService#hasAnyRoles(Collection)
     * @see IAuthenticationService#hasAnyRoles(Collection, int)
     *
     * @param roles проверяемые роли
     * @return true, если у пользователя есть все роли из {@code roles}, иначе false
     */
    boolean hasAllRoles(Collection<String> roles);

    /**
     * Проверить наличие хотя бы одной роли из {@code roles} у аутентифицированного пользователя
     * @see IAuthenticationService#hasRole(String)
     * @see IAuthenticationService#hasAllRoles(Collection)
     * @see IAuthenticationService#hasAnyRoles(Collection, int)
     *
     * @param roles проверяемые роли
     * @return true, если у пользователя есть хотя бы одна из ролей {@code roles}, иначе false
     */
    boolean hasAnyRoles(Collection<String> roles);

    /**
     * Проверить наличие хотя бы {@code count} ролей у аутентифицированного пользователя
     * @see IAuthenticationService#hasRole(String)
     * @see IAuthenticationService#hasAllRoles(Collection)
     * @see IAuthenticationService#hasAnyRoles(Collection)
     *
     * @param roles проверяемые роли
     * @param count количество ролей из списка, которыми должен обладать пользователь
     * @return true, если у пользователя есть хотя бы {@code count} ролей из {@code roles}, иначе false
     */
    boolean hasAnyRoles(Collection<String> roles, int count);

    /**
     * Проверить наличие права у аутентифицированного пользователя
     * @see IAuthenticationService#hasAllPermissions(Collection)
     * @see IAuthenticationService#hasAnyPermissions(Collection)
     * @see IAuthenticationService#hasAnyPermissions(Collection, int)
     *
     * @param permission право на проверку
     * @return true, если у пользователя есть данное право, иначе false
     */
    boolean hasPermission(String permission);

    /**
     * Проверить наличие нескольких прав у аутентифицированного пользователя
     * @see IAuthenticationService#hasPermission(String)
     * @see IAuthenticationService#hasAnyPermissions(Collection)
     * @see IAuthenticationService#hasAnyPermissions(Collection, int)
     *
     * @param permissions права на проверку
     * @return true, если у пользователя есть все права из {@code permissions}, иначе false
     */
    boolean hasAllPermissions(Collection<String> permissions);

    /**
     * Проверить наличие хотя бы одного права из {@code permissions} у аутентифицированного
     * пользователя
     * @see IAuthenticationService#hasPermission(String)
     * @see IAuthenticationService#hasAllPermissions(Collection)
     * @see IAuthenticationService#hasAnyPermissions(Collection, int)
     *
     * @param permissions права на проверку
     * @return true, если у пользователя есть хотя бы одно право из {@code permissions}, иначе false
     */
    boolean hasAnyPermissions(Collection<String> permissions);

    /**
     * Проверить наличие хотя бы {@code count} прав у аутентифицированного пользователя из
     * {@code permissions}
     * @see IAuthenticationService#hasPermission(String)
     * @see IAuthenticationService#hasAllPermissions(Collection)
     * @see IAuthenticationService#hasAnyPermissions(Collection)
     *
     * @param permissions права на проверку
     * @param count количество прав из списка, которыми должен обладать пользователь
     * @return true, если у пользователя есть хотя бы {@code count} прав из {@code permissions}
     */
    boolean hasAnyPermissions(Collection<String> permissions, int count);
}
