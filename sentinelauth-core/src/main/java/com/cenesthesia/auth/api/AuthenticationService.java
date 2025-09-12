package com.cenesthesia.auth.api;

import com.cenesthesia.auth.common.AuthPrincipal;
import com.cenesthesia.auth.common.Credentials;
import com.cenesthesia.auth.core.AuthException;
import com.cenesthesia.auth.core.SimpleAuthenticationProcessor;
import com.cenesthesia.auth.core.SimpleAuthorizationProcessor;

import java.util.Collection;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Версия сервиса аутентификации для одно-пользовательских Desktop-приложений
 * !(Нестабильный, в будущем будет заменена или модифицирована)
 *
 * @author Cenesthesia
 * @version 1.0
 */
public abstract class AuthenticationService {
    protected IAuthUserRepository repository;
    protected IAuthenticationProcessor authenticate;
    protected IAuthorizationProcessor authorization;
    protected AtomicReference<ICredentialsProvider> credentialsProvider = new AtomicReference<>(null);
    protected final AtomicReference<AuthPrincipal> principal = new AtomicReference<>(null);
    protected final AtomicReference<Boolean> isAuthenticated = new AtomicReference<>(false);
    protected final AtomicReference<Boolean> isInitialized = new AtomicReference<>(false);
    protected final AtomicReference<Boolean> requireBreak = new AtomicReference<>(false);

    protected static volatile AuthenticationService INSTANCE;

    public synchronized void initialize(IAuthUserRepository repository) {
        if (isInitialized.get()) {
            throw new IllegalStateException("SimpleAuthenticationService has already been initialized");
        }
        this.repository = repository;
        this.authenticate = new SimpleAuthenticationProcessor();
        this.authorization = new SimpleAuthorizationProcessor();

        isInitialized.set(true);
    }

    public synchronized void initialize(IAuthUserRepository repository, IAuthenticationProcessor authenticate) {
        if (isInitialized.get()) {
            throw new IllegalStateException("SimpleAuthenticationService has already been initialized");
        }
        this.repository = repository;
        this.authenticate = authenticate;
        this.authorization = new SimpleAuthorizationProcessor();

        isInitialized.set(true);
    }

    public synchronized void initialize(IAuthUserRepository repository, IAuthorizationProcessor authorization) {
        if (isInitialized.get()) {
            throw new IllegalStateException("SimpleAuthenticationService has already been initialized");
        }
        this.repository = repository;
        this.authenticate = new SimpleAuthenticationProcessor();
        this.authorization = authorization;

        isInitialized.set(true);
    }

    public synchronized void initialize(IAuthUserRepository repository, IAuthenticationProcessor authenticate,
                                        IAuthorizationProcessor authorization) {
        if (isInitialized.get()) {
            throw new IllegalStateException("SimpleAuthenticationService has already been initialized");
        }
        this.repository = repository;
        this.authenticate = authenticate;
        this.authorization = authorization;

        isInitialized.set(true);
    }

    public synchronized void setCredentialsProvider(ICredentialsProvider credentialsProvider) {
        this.credentialsProvider.set(credentialsProvider);
    }

    protected void checkInitialization() {
        if (!isInitialized.get()) {
            throw new IllegalStateException("SimpleAuthenticationService not initialized. Call initialize() before using");
        }
    }

    protected void checkAuthenticate() {
        if (!isAuthenticated.get()) {
            throw new AuthException("Operation not possible. User not authenticated.");
        }
    }

    protected void checkCredentialsProvider() {
        if (credentialsProvider.get() == null) {
            throw new AuthException("Source of credentials not specified. Call setCredentialsProvider() before using");
        }
    }

    protected void resetState() {
        principal.set(null);
        isAuthenticated.set(false);
    }

    /**
     * Выполняет аутентификацию пользователя
     * @see AuthenticationService#authenticateWithContext(Credentials, Object)
     *
     * @param credentials реквизиты пользователя
     * @return true, если аутентификация успешна, иначе false
     */
    public abstract boolean authenticate(Credentials credentials);

    public abstract boolean requireAuthenticate() throws AuthException;

    /**
     * Выполняет аутентификацию пользователя с учетом дополнительного контекста. Заделка для
     * кастомных сервисов. По умолчанию функционал аналогичен {@link AuthenticationService#authenticate(Credentials)}
     * @see AuthenticationService#authenticate(Credentials)
     *
     * @param credentials реквизиты аутентификации
     * @param context контекст
     * @return true, если аутентификация успешна, иначе false
     */
    public boolean authenticateWithContext(Credentials credentials, Object context) {
        return authenticate(credentials);
    }

    public boolean requireAuthenticateWithContext(Object context) {
        return requireAuthenticate();
    }

    /**
     * Завершает сеанс аутентификации пользователя
     *
     * @return true, если сеанс успешно завершен, иначе false
     */
    public abstract boolean logout();

    /**
     * Завершает сеанс аутентификации пользователя по его уникальному идентификатору
     * !!(Наработка на будущее)
     *
     * @param id идентификатор сеанса
     * @return true, если сеанс успешно завершен, иначе false
     */
    public abstract boolean logout(String id);

    /**
     * Проверяет статус аутентификации в системе
     *
     * @return true, если есть аутентифицированный пользователь, иначе false
     */
    public abstract boolean verifyAuth();

    /**
     * Проверяет наличие роли у аутентифицированного пользователя
     * @see AuthenticationService#hasAllRoles(Collection)
     * @see AuthenticationService#hasAnyRole(Collection)
     * @see AuthenticationService#hasAnyRoles(Collection, int)
     * @see AuthenticationService#hasRoleWithContext(String, Object)
     *
     * @param role проверяемая роль
     * @return true, если у пользователя есть роль {@code role}, иначе false
     */
    public abstract boolean hasRole(String role);

    public abstract boolean requireRole(String role);

    /**
     * Проверяет наличие нескольких ролей у аутентифицированного пользователя
     * @see AuthenticationService#hasRole(String)
     * @see AuthenticationService#hasAnyRole(Collection)
     * @see AuthenticationService#hasAnyRoles(Collection, int)
     * @see AuthenticationService#hasRoleWithContext(String, Object)
     *
     * @param roles проверяемые роли
     * @return true, если у пользователя есть все роли из {@code roles}, иначе false
     */
    public abstract boolean hasAllRoles(Collection<String> roles);

    public abstract boolean requireAllRoles(Collection<String> roles);

    /**
     * Проверяет наличие хотя бы одной роли из {@code roles} у аутентифицированного пользователя
     * @see AuthenticationService#hasRole(String)
     * @see AuthenticationService#hasAllRoles(Collection)
     * @see AuthenticationService#hasAnyRoles(Collection, int)
     * @see AuthenticationService#hasRoleWithContext(String, Object)
     *
     * @param roles проверяемые роли
     * @return true, если у пользователя есть хотя бы одна из ролей {@code roles}, иначе false
     */
    public abstract boolean hasAnyRole(Collection<String> roles);

    public abstract boolean requireAnyRole(Collection<String> roles);

    /**
     * Проверяет наличие хотя бы {@code count} ролей у аутентифицированного пользователя
     * @see AuthenticationService#hasRole(String)
     * @see AuthenticationService#hasAllRoles(Collection)
     * @see AuthenticationService#hasAnyRole(Collection)
     * @see AuthenticationService#hasRoleWithContext(String, Object)
     *
     * @param roles проверяемые роли
     * @param count количество ролей из списка, которыми должен обладать пользователь
     * @return true, если у пользователя есть хотя бы {@code count} ролей из {@code roles}, иначе false
     */
    public abstract boolean hasAnyRoles(Collection<String> roles, int count);

    public abstract boolean requireAnyRoles(Collection<String> roles, int count);

    /**
     * Проверяет наличие права у аутентифицированного пользователя
     * @see AuthenticationService#hasAllPermissions(Collection)
     * @see AuthenticationService#hasAnyPermission(Collection)
     * @see AuthenticationService#hasAnyPermissions(Collection, int)
     * @see AuthenticationService#hasPermissionWithContext(String, Object)
     *
     * @param permission право на проверку
     * @return true, если у пользователя есть данное право, иначе false
     */
    public abstract boolean hasPermission(String permission);

    public abstract boolean requirePermission(String permission);

    /**
     * Проверяет наличие нескольких прав у аутентифицированного пользователя
     * @see AuthenticationService#hasPermission(String)
     * @see AuthenticationService#hasAnyPermission(Collection)
     * @see AuthenticationService#hasAnyPermissions(Collection, int)
     * @see AuthenticationService#hasPermissionWithContext(String, Object)
     *
     * @param permissions права на проверку
     * @return true, если у пользователя есть все права из {@code permissions}, иначе false
     */
    public abstract boolean hasAllPermissions(Collection<String> permissions);

    public abstract boolean requireAllPermissions(Collection<String> permissions);

    /**
     * Проверяет наличие хотя бы одного права из {@code permissions} у аутентифицированного
     * пользователя
     * @see AuthenticationService#hasPermission(String)
     * @see AuthenticationService#hasAllPermissions(Collection)
     * @see AuthenticationService#hasAnyPermissions(Collection, int)
     * @see AuthenticationService#hasPermissionWithContext(String, Object)
     *
     * @param permissions права на проверку
     * @return true, если у пользователя есть хотя бы одно право из {@code permissions}, иначе false
     */
    public abstract boolean hasAnyPermission(Collection<String> permissions);

    public abstract boolean requireAnyPermission(Collection<String> permissions);

    /**
     * Проверяет наличие хотя бы {@code count} прав у аутентифицированного пользователя из
     * {@code permissions}
     * @see AuthenticationService#hasPermission(String)
     * @see AuthenticationService#hasAllPermissions(Collection)
     * @see AuthenticationService#hasAnyPermission(Collection)
     * @see AuthenticationService#hasPermissionWithContext(String, Object)
     *
     * @param permissions права на проверку
     * @param count количество прав из списка, которыми должен обладать пользователь
     * @return true, если у пользователя есть хотя бы {@code count} прав из {@code permissions}
     */
    public abstract boolean hasAnyPermissions(Collection<String> permissions, int count);

    public abstract boolean requireAnyPermissions(Collection<String> permissions, int count);

    /**
     * Проверяет наличие у пользователя роли с дополнительной контекстной информацией.
     * Заделка для кастомных авторизационных сервисов. По умолчанию функционал аналогичен
     * {@link AuthenticationService#hasRole(String)}
     * @see AuthenticationService#hasRole(String)
     * @see AuthenticationService#hasAllRoles(Collection)
     * @see AuthenticationService#hasAnyRole(Collection)
     * @see AuthenticationService#hasAnyRoles(Collection, int)
     *
     * @param role проверяемая роль
     * @param context контекст
     * @return true, если у пользователя есть роль {@code role} в рамках контекста, иначе false
     */
    public boolean hasRoleWithContext(String role, Object context) {
        return hasRole(role);
    }

    public boolean requireRoleWithContext(String role, Object context) {
        return requireRole(role);
    }

    /**
     * Проверяет наличие права у пользователя с дополнительной контекстной информацией.
     * Заделка для кастомных авторизационных сервисов. По умолчанию функционал аналогичен
     * {@link AuthenticationService#hasPermission(String)}
     * @see AuthenticationService#hasPermission(String)
     * @see AuthenticationService#hasAllPermissions(Collection)
     * @see AuthenticationService#hasAnyPermission(Collection)
     * @see AuthenticationService#hasAnyPermissions(Collection, int)
     *
     * @param permission право на проверку
     * @param context контекст
     * @return true, если у пользователя есть роль {@code role} в рамках контекста, иначе false
     */
    public boolean hasPermissionWithContext(String permission, Object context) {
        return hasPermission(permission);
    }

    public boolean requirePermissionWithContext(String permission, Object context) {
        return requirePermission(permission);
    }
}
