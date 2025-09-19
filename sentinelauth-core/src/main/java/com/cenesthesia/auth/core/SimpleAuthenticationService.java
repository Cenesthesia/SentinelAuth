package com.cenesthesia.auth.core;

import com.cenesthesia.auth.api.*;
import com.cenesthesia.auth.common.AuthPrincipal;
import com.cenesthesia.auth.common.AuthResult;
import com.cenesthesia.auth.common.Credentials;
import com.cenesthesia.auth.utils.PasswordSecurityUtils;

import java.util.Arrays;
import java.util.Collection;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * Потокобезопасный сервис аутентификации для простых однопользовательских приложений.
 * <p>
 * Предоставляет единую точку входа для операций идентификации, аутентификации и авторизации.
 * Реализован как Singleton для обеспечения глобального доступа из различных частей приложения.
 * </p>
 * <p>
 * <b>Особенности потокобезопасности:</b>
 * <ul>
 *     <li>Использует {@link ReentrantReadWriteLock} для разделения блокировок чтения/записи</li>
 *     <li>Атомарные операции с {@link AtomicReference} для отдельных полей</li>
 *     <li>Иммутабельные возвращаемые значения {@link AuthResult}</li>
 *     <li>Гарантированная очистка чувствительных данных в final-блоках</li>
 * </ul>
 * </p>
 *
 * <p><b>Пример использования:</b></p>
 * <pre>
 * {@code
 * // Инициализация
 * IAuthUserRepository repo = new MyUserRepository();
 * SimpleAuthenticationService service = SimpleAuthenticationService.getInstance();
 * AuthResult initResult = service.initialize(repo);
 *
 * // Установка источника реквизитов (для запросов начинающихся с require*. !* не обязательно для других методов)
 * SimpleAuthenticationService.setCredentialsProvider(new ConsoleCredentialsProvider());
 *
 * // Аутентификация
 * Credentials credentials = new Credentials("user".toCharArray(), "Password123#".toCharArray());
 * AuthResult authResult = service.authenticate(credentials);
 * // Или, если установлен источник реквизитов:
 * // AuthResult authResult = service.requireAuthenticate();
 *
 * if (authResult.isSuccess()) {
 *     // Проверка прав без проверки аутентификации пользователя
 *     AuthResult roleResult = service.hasRole("admin");
*      if (roleResult.isSuccess()) {
 *          // Доступ разрешен
 *     }
 * }
 * // Вместо разделения процессов аутентификации и авторизации можно использовать методы начинающиеся с require* (!Должен быть установлен источник реквизитов через setCredentialsProvider(ICredentialsProvider)).
 * // Данные методы в случае, если ранее пользователь не был аутентифицирован пытаются пройти аутентификацию на основе реквизитов из источники ICredentialsProvider.
 * // AuthResult roleResult = service.requireRole("admin");
 * // if (roleResult.isSuccess()) {
 * //     // Доступ разрешен
 * // }
 *
 * // Выход из учетной записи пользователя
 * service.logout();
 * }
 * </pre>
 *
 * @author Cenesthesia
 * @version 1.0
 * @see AuthResult
 * @see IAuthUserRepository
 * @see IAuthenticationProcessor
 * @see IAuthorizationProcessor
 */
public final class SimpleAuthenticationService {

    private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock(true);
    private IAuthUserRepository repository;
    private IAuthenticationProcessor authenticate;
    private IAuthorizationProcessor authorization;
    private final AtomicReference<ICredentialsProvider> credentialsProvider = new AtomicReference<>(null);
    private final AtomicReference<AuthPrincipal> principal = new AtomicReference<>(null);
    private final AtomicReference<Boolean> isAuthenticated = new AtomicReference<>(false);
    private final AtomicReference<Boolean> isInitialized = new AtomicReference<>(false);

    private static volatile SimpleAuthenticationService INSTANCE;

    /**
     * Конструктор - приватный для реализации Singleton
     */
    private SimpleAuthenticationService() {

    }

    /**
     * Инициализирует сервис с репозиторием пользователей и процессорами по умолчанию ({@link SimpleAuthenticationProcessor}, {@link SimpleAuthorizationProcessor})
     *
     * @param repository репозиторий для работы с пользователями
     * @return результат операции инициализации {@link AuthResult}
     * @throws NullPointerException, если любой из параметров null
     */
    public synchronized AuthResult initialize(IAuthUserRepository repository) {
        return initialize(repository, new SimpleAuthenticationProcessor(), new SimpleAuthorizationProcessor());
    }

    /**
     * Инициализирует сервис с репозиторием пользователей кастомным процессором аутентификации ({@link SimpleAuthenticationProcessor}
     *
     * @param repository репозиторий для работы с пользователями
     * @param authenticate кастомный процессор аутентификации
     * @return результат операции инициализации {@link AuthResult}
     * @throws NullPointerException, если любой из параметров null
     */
    public synchronized void initialize(IAuthUserRepository repository, IAuthenticationProcessor authenticate) {
        if (isInitialized.get()) {
            throw new IllegalStateException("SimpleAuthenticationService has already been initialized");
        }
        this.repository = Objects.requireNonNull(repository, "Initialize error: user repository cannot be null");
        this.authenticate = Objects.requireNonNull(authenticate, "Initialize error: authenticate processor cannot be null");
        this.authorization = new SimpleAuthorizationProcessor();

        isInitialized.set(true);
    }

    /**
     * Инициализирует сервис с репозиторием пользователей кастомным процессором авторизации ({@link SimpleAuthorizationProcessor}
     *
     * @param repository репозиторий для работы с пользователями
     * @param authorization кастомный процессор авторизации
     * @return результат операции инициализации {@link AuthResult}
     * @throws NullPointerException, если любой из параметров null
     */
    public synchronized void initialize(IAuthUserRepository repository, IAuthorizationProcessor authorization) {
        if (isInitialized.get()) {
            throw new IllegalStateException("SimpleAuthenticationService has already been initialized");
        }
        this.repository = Objects.requireNonNull(repository, "Initialize error: user repository cannot be null");
        this.authenticate = new SimpleAuthenticationProcessor();
        this.authorization = Objects.requireNonNull(authorization, "Initialize error: authorization processor cannot be null");

        isInitialized.set(true);
    }

    /**
     * Инициализирует сервис с кастомными процессорами аутентификации, авторизации и пользовательским репозиторием.
     * @see SimpleAuthenticationService#initialize(IAuthUserRepository)
     * @see SimpleAuthenticationService#initialize(IAuthUserRepository, IAuthenticationProcessor)
     * @see SimpleAuthenticationService#initialize(IAuthUserRepository, IAuthorizationProcessor)
     *
     * @param repository репозиторий для работы с пользователями
     * @param authenticate кастомный процессор аутентификации
     * @param authorization кастомный процессор авторизации
     * @return результат операции инициализации {@link AuthResult}
     * @throws  NullPointerException, если любой из параметров null
     */
    public synchronized AuthResult initialize(IAuthUserRepository repository, IAuthenticationProcessor authenticate,
                                        IAuthorizationProcessor authorization) {
        lock.writeLock().lock();
        try {
            if (isInitialized.get()) {
                return AuthResult.failure("SimpleAuthenticationService has already been initialized");
            }

            this.repository = Objects.requireNonNull(repository, "Initialize error: user repository cannot be null");
            this.authenticate = Objects.requireNonNull(authenticate, "Initialize error: authenticate processor cannot be null");
            this.authorization = Objects.requireNonNull(authorization, "Initialize error: authorization processor cannot be null");

            isInitialized.set(true);
            return  AuthResult.success("Service initialized successfully");
        } catch (Exception e) {
            return AuthResult.failure("Initialization failed", e);
        } finally {
            lock.writeLock().unlock();
        }
    }

    /**
     * Возвращает Singleton экземпляр сервиса аутентификации.
     * Использует double-checked locking для потокобезопасности.
     *
     * @return Singleton экземпляр {@link SimpleAuthenticationService}
     */
    public static SimpleAuthenticationService getInstance() {
        if (INSTANCE == null) {
            synchronized (SimpleAuthenticationService.class) {
                if (INSTANCE == null) {
                    INSTANCE = new SimpleAuthenticationService();
                }
            }
        }
        return INSTANCE;
    }

    /**
     * Устанавливает источник реквизитов для автоматической аутентификации.
     * <p>
     * <b>ВАЖНО!: обязателен для предоставления корректной работы методов начинающихся с required*.</b>
     * </p>
     *
     * @param credentialsProvider источник реквизитов
     * @return результат операции установки {@link AuthResult}
     */
    public synchronized AuthResult setCredentialsProvider(ICredentialsProvider credentialsProvider) {
        this.credentialsProvider.set(credentialsProvider);
        return AuthResult.success("Credentials provider set successfully");
    }

    /**
     * Проверяет, инициализирован ли сервис.
     *
     * @return успешный {@link AuthResult}, если сервис инициализирован, иначе ошибочный
     */
    private AuthResult checkInitialization() {
        if (!isInitialized.get()) {
            return AuthResult.failure("SimpleAuthenticationService not initialized. Call initialize() before using");
        }
        return AuthResult.success();
    }

    /**
     * Проверяет, аутентифицирован ли пользователь.
     *
     * @return успешный {@link AuthResult}, если пользователь аутентифицирован, иначе ошибочный
     */
    private AuthResult checkAuthenticate() {
        if (!isAuthenticated.get()) {
            return AuthResult.failure("Operation not possible. User not authenticated.");
        }
        return AuthResult.success();
    }

    /**
     * Проверяет, установлен ли источник реквизитов.
     *
     * @return успешный {@link AuthResult}, если источник установлен, иначе ошибочный
     */
    private AuthResult checkCredentialsProvider() {
        if (credentialsProvider.get() == null) {
            return AuthResult.failure("Source of credentials not specified. Call setCredentialsProvider() before using");
        }
        return AuthResult.success();
    }

    /**
     * Сбрасывает состояние аутентификации и очищает чувствительные данные.
     */
    private void resetState() {
        AuthPrincipal oldPrincipal = principal.getAndSet(null);
        if (oldPrincipal != null) {
            cleanupPrincipal(oldPrincipal);
        }
        isAuthenticated.set(false);
    }

    /**
     * Безопасно очищает чувствительные данные из объекта {@link AuthPrincipal}.
     *
     * @param principal учетные данные с чувствительными данными для очистки
     */
    private void cleanupPrincipal(AuthPrincipal principal) {
        PasswordSecurityUtils.clearChars(principal.getId());
        PasswordSecurityUtils.clearChars(principal.getUsername());
        PasswordSecurityUtils.clearBytes(principal.getPasswordHash());
        PasswordSecurityUtils.clearBytes(principal.getSalt());
        principal.setRoles(null);
        principal.setPermissions(null);
    }

    /**
     * Выполняет аутентификацию пользователя по предоставленным реквизитам.
     * <p>
     * <b>Потокобезопасность: </b>использует write lock для изменения состояния аутентификации.
     * </p>
     * @see SimpleAuthenticationService#authenticateWithContext(Credentials, Object)
     *
     * @param credentials реквизиты пользователя
     * @return результат аутентификации {@link AuthResult} с детальной информации
     */
    public AuthResult authenticate(Credentials credentials) {
        lock.writeLock().lock();
        try {
            AuthResult initCheck = checkInitialization();
            if (!initCheck.isSuccess()) {
                return initCheck;
            }
            resetState();

            try {
                String userName = new String(credentials.getUserIdentifier());
                Optional<AuthPrincipal> user = repository.findByUsername(userName);
                if (user.isEmpty())
                    return AuthResult.failure(String.format("The user with the identifier %s was not found in the repository",
                            new String(credentials.getUserIdentifier())));

                AuthResult authResult = authenticate.authenticate(user.get(), credentials);
                if (authResult.isSuccess()) {
                    principal.set(user.get());
                    isAuthenticated.set(true);
                    return AuthResult.success("Authenticate successful");
                } else {
                    resetState();
                    return AuthResult.failure("Authenticate failed - invalid credentials")
                            .withMessages(authResult.getMessages())
                            .withExceptions(authResult.getExceptions());
                }
            } catch (Exception e) {
                resetState();
                return AuthResult.failure(String.format("Authentication error: %s", e.getMessage()), e);
            }
        } finally {
            lock.writeLock().unlock();
        }
    }

    /**
     * Выполняет аутентификацию пользователя с использованием установленного источника реквизитов.
     * <p>
     * <b>Потокобезопасность: </b>Длительная операция получения реквизитов выполняется вне критической секции для
     * минимизации времени блокировки.
     * </p>
     * @see SimpleAuthenticationService#authenticateWithContext(Credentials, Object)
     *
     * @return результат аутентификации {@link AuthResult} с детальной информации
     */
    public AuthResult requireAuthenticate() throws AuthException {
        lock.writeLock().lock();
        try {
            AuthResult initChack = checkInitialization();
            if (!initChack.isSuccess()) {
                return initChack;
            }

            AuthResult providerCheck = checkCredentialsProvider();
            if (!providerCheck.isSuccess()) {
                return providerCheck;
            }
            resetState();

            try {
                Credentials credentials;
                try {
                    credentials = credentialsProvider.get().provideCredentials();
                } catch (Exception e) {
                    return AuthResult.failure(String.format("Failed to obtain credentials. Exception: %s", e.getMessage()), e);
                }
                String username = new String(credentials.getUserIdentifier());
                Optional<AuthPrincipal> user = repository.findByUsername(username);
                if (user.isEmpty())
                    return AuthResult.failure(String.format("The user with the identifier %s was not found in the repository",
                            username));

                AuthResult authResult = authenticate.authenticate(user.get(), credentials);
                if (authResult.isSuccess()) {
                    principal.set(user.get());
                    isAuthenticated.set(true);
                    return AuthResult.success("Authentication successful"   );
                } else {
                    resetState();
                    return AuthResult.failure("Authentication failed - invalid credentials")
                            .withMessages(authResult.getMessages())
                            .withExceptions(authResult.getExceptions());
                }
            } catch (Exception e) {
                resetState();
                return AuthResult.failure(String.format("Authentication error: %s", e.getMessage()), e);
            }
        } finally {
            lock.writeLock().unlock();
        }
    }

    /**
     * Выполняет аутентификацию пользователя с учетом дополнительного контекста. Заделка для
     * кастомных сервисов. По умолчанию делегирует вызов методу {@link SimpleAuthenticationService#authenticate(Credentials)}
     * @see SimpleAuthenticationService#authenticate(Credentials)
     *
     * @param credentials реквизиты аутентификации
     * @param context дополнительный контекст
     * @return результат аутентификации {@link AuthResult} с детальной информации
     */
    public AuthResult authenticateWithContext(Credentials credentials, Object context) {
        AuthResult result = authenticate(credentials);
        return result.isSuccess() ?
                result.withMessage("Contextual authentication performed") :
                result.withMessage("Contextual authentication failed");
    }

    /**
     * Выполняет аутентификацию пользователя с использованием источника реквизитов и дополнительного контекста. Заделка для
     * кастомных сервисов. По умолчанию делегирует вызов методу {@link SimpleAuthenticationService#authenticate(Credentials)}
     * @see SimpleAuthenticationService#authenticate(Credentials)
     *
     * @param context дополнительный контекст
     * @return результат аутентификации {@link AuthResult} с детальной информации
     */
    public AuthResult requireAuthenticateWithContext(Object context) {
        AuthResult result = requireAuthenticate();
        return result.isSuccess() ?
                result.withMessage("Contextual authentication performed") :
                result.withMessage("Contextual authentication failed");
    }

    /**
     * Завершает сеанс аутентификации пользователя
     *
     * @return true, если сеанс успешно завершен, иначе false
     */
    public synchronized boolean logout() {
        try {
            checkInitialization();
            checkAuthenticate();
            resetState();
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Завершает сеанс аутентификации пользователя по его уникальному идентификатору
     * !!(Наработка на будущее)
     *
     * @param id идентификатор сеанса
     * @return true, если сеанс успешно завершен, иначе false
     */
    public synchronized boolean logout(char[] id) {
        try {
            checkInitialization();
            checkAuthenticate();
            if (Arrays.equals(principal.get().getId(), id) || Arrays.equals(principal.get().getUsername(), id)) {
                resetState();
                return true;
            } else {
                return false;
            }
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Проверяет статус аутентификации в системе
     *
     * @return true, если есть аутентифицированный пользователь, иначе false
     */
    public synchronized boolean verifyAuth() {
        checkInitialization();
        return isAuthenticated.get();
    }

    /**
     * Проверяет наличие роли у аутентифицированного пользователя
     * @see SimpleAuthenticationService#hasAllRoles(Collection)
     * @see SimpleAuthenticationService#hasAnyRole(Collection)
     * @see SimpleAuthenticationService#hasAnyRoles(Collection, int)
     * @see SimpleAuthenticationService#hasRoleWithContext(String, Object)
     *
     * @param role проверяемая роль
     * @return true, если у пользователя есть роль {@code role}, иначе false
     */
    public synchronized boolean hasRole(String role) {
        checkInitialization();
        checkAuthenticate();
        return authorization.hasRole(principal.get(), role);
    }

    public boolean requireRole(String role) {
        checkInitialization();
        if (!isAuthenticated.get())
            requireAuthenticate();
        if (!isAuthenticated.get()) {
            return false;
        }
        return authorization.hasRole(principal.get(), role);
    }

    /**
     * Проверяет наличие нескольких ролей у аутентифицированного пользователя
     * @see SimpleAuthenticationService#hasRole(String)
     * @see SimpleAuthenticationService#hasAnyRole(Collection)
     * @see SimpleAuthenticationService#hasAnyRoles(Collection, int)
     * @see SimpleAuthenticationService#hasRoleWithContext(String, Object)
     *
     * @param roles проверяемые роли
     * @return true, если у пользователя есть все роли из {@code roles}, иначе false
     */
    public synchronized boolean hasAllRoles(Collection<String> roles) {
        checkInitialization();
        checkAuthenticate();
        return authorization.hasAllRoles(principal.get(), roles);
    }

    public boolean requireAllRoles(Collection<String> roles) {
        checkInitialization();
        if (!isAuthenticated.get())
            requireAuthenticate();
        if (!isAuthenticated.get()) {
            return false;
        }
        return authorization.hasAllRoles(principal.get(), roles);
    }

    /**
     * Проверяет наличие хотя бы одной роли из {@code roles} у аутентифицированного пользователя
     * @see SimpleAuthenticationService#hasRole(String)
     * @see SimpleAuthenticationService#hasAllRoles(Collection)
     * @see SimpleAuthenticationService#hasAnyRoles(Collection, int)
     * @see SimpleAuthenticationService#hasRoleWithContext(String, Object)
     *
     * @param roles проверяемые роли
     * @return true, если у пользователя есть хотя бы одна из ролей {@code roles}, иначе false
     */
    public synchronized boolean hasAnyRole(Collection<String> roles) {
        checkInitialization();
        checkAuthenticate();
        return authorization.hasAnyRole(principal.get(), roles);
    }

    public boolean requireAnyRole(Collection<String> roles) {
        checkInitialization();
        if (!isAuthenticated.get())
            requireAuthenticate();
        if (!isAuthenticated.get()) {
            return false;
        }
        return authorization.hasAnyRole(principal.get(), roles);
    }

    /**
     * Проверяет наличие хотя бы {@code count} ролей у аутентифицированного пользователя
     * @see SimpleAuthenticationService#hasRole(String)
     * @see SimpleAuthenticationService#hasAllRoles(Collection)
     * @see SimpleAuthenticationService#hasAnyRole(Collection)
     * @see SimpleAuthenticationService#hasRoleWithContext(String, Object)
     *
     * @param roles проверяемые роли
     * @param count количество ролей из списка, которыми должен обладать пользователь
     * @return true, если у пользователя есть хотя бы {@code count} ролей из {@code roles}, иначе false
     */
    public synchronized boolean hasAnyRoles(Collection<String> roles, int count) {
        checkInitialization();
        checkAuthenticate();
        return authorization.hasAnyRoles(principal.get(), roles, count);
    }

    public boolean requireAnyRoles(Collection<String> roles, int count) {
        checkInitialization();
        if (!isAuthenticated.get())
            requireAuthenticate();
        if (!isAuthenticated.get()) {
            return false;
        }
        return authorization.hasAnyRoles(principal.get(), roles, count);
    }

    /**
     * Проверяет наличие права у аутентифицированного пользователя
     * @see SimpleAuthenticationService#hasAllPermissions(Collection)
     * @see SimpleAuthenticationService#hasAnyPermission(Collection)
     * @see SimpleAuthenticationService#hasAnyPermissions(Collection, int)
     * @see SimpleAuthenticationService#hasPermissionWithContext(String, Object)
     *
     * @param permission право на проверку
     * @return true, если у пользователя есть данное право, иначе false
     */
    public synchronized boolean hasPermission(String permission) {
        checkInitialization();
        checkAuthenticate();
        return authorization.hasPermission(principal.get(), permission);
    }

    public boolean requirePermission(String permission) {
        checkInitialization();
        if (!isAuthenticated.get())
            requireAuthenticate();
        if (!isAuthenticated.get()) {
            return false;
        }
        return authorization.hasPermission(principal.get(), permission);
    }

    /**
     * Проверяет наличие нескольких прав у аутентифицированного пользователя
     * @see SimpleAuthenticationService#hasPermission(String)
     * @see SimpleAuthenticationService#hasAnyPermission(Collection)
     * @see SimpleAuthenticationService#hasAnyPermissions(Collection, int)
     * @see SimpleAuthenticationService#hasPermissionWithContext(String, Object)
     *
     * @param permissions права на проверку
     * @return true, если у пользователя есть все права из {@code permissions}, иначе false
     */
    public synchronized boolean hasAllPermissions(Collection<String> permissions) {
        checkInitialization();
        checkAuthenticate();
        return authorization.hasAllPermissions(principal.get(), permissions);
    }

    public boolean requireAllPermissions(Collection<String> permissions) {
        checkInitialization();
        if (!isAuthenticated.get())
            requireAuthenticate();
        if (!isAuthenticated.get()) {
            return false;
        }
        return authorization.hasAllPermissions(principal.get(), permissions);
    }

    /**
     * Проверяет наличие хотя бы одного права из {@code permissions} у аутентифицированного
     * пользователя
     * @see SimpleAuthenticationService#hasPermission(String)
     * @see SimpleAuthenticationService#hasAllPermissions(Collection)
     * @see SimpleAuthenticationService#hasAnyPermissions(Collection, int)
     * @see SimpleAuthenticationService#hasPermissionWithContext(String, Object)
     *
     * @param permissions права на проверку
     * @return true, если у пользователя есть хотя бы одно право из {@code permissions}, иначе false
     */
    public synchronized boolean hasAnyPermission(Collection<String> permissions) {
        checkInitialization();
        checkAuthenticate();
        return authorization.hasAnyPermission(principal.get(), permissions);
    }

    public boolean requireAnyPermission(Collection<String> permissions) {
        checkInitialization();
        if (!isAuthenticated.get())
            requireAuthenticate();
        if (!isAuthenticated.get()) {
            return false;
        }
        return authorization.hasAnyPermission(principal.get(), permissions);
    }

    /**
     * Проверяет наличие хотя бы {@code count} прав у аутентифицированного пользователя из
     * {@code permissions}
     * @see SimpleAuthenticationService#hasPermission(String)
     * @see SimpleAuthenticationService#hasAllPermissions(Collection)
     * @see SimpleAuthenticationService#hasAnyPermission(Collection)
     * @see SimpleAuthenticationService#hasPermissionWithContext(String, Object)
     *
     * @param permissions права на проверку
     * @param count количество прав из списка, которыми должен обладать пользователь
     * @return true, если у пользователя есть хотя бы {@code count} прав из {@code permissions}
     */
    public synchronized boolean hasAnyPermissions(Collection<String> permissions, int count) {
        checkInitialization();
        checkAuthenticate();
        return authorization.hasAnyPermissions(principal.get(), permissions, count);
    }

    public boolean requireAnyPermissions(Collection<String> permissions, int count) {
        checkInitialization();
        if (!isAuthenticated.get())
            requireAuthenticate();
        if (!isAuthenticated.get()) {
            return false;
        }
        return authorization.hasAnyPermissions(principal.get(), permissions, count);
    }

    /**
     * Проверяет наличие у пользователя роли с дополнительной контекстной информацией.
     * Заделка для кастомных авторизационных сервисов. По умолчанию функционал аналогичен
     * {@link SimpleAuthenticationService#hasRole(String)}
     * @see SimpleAuthenticationService#hasRole(String)
     * @see SimpleAuthenticationService#hasAllRoles(Collection)
     * @see SimpleAuthenticationService#hasAnyRole(Collection)
     * @see SimpleAuthenticationService#hasAnyRoles(Collection, int)
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
     * {@link SimpleAuthenticationService#hasPermission(String)}
     * @see SimpleAuthenticationService#hasPermission(String)
     * @see SimpleAuthenticationService#hasAllPermissions(Collection)
     * @see SimpleAuthenticationService#hasAnyPermission(Collection)
     * @see SimpleAuthenticationService#hasAnyPermissions(Collection, int)
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
