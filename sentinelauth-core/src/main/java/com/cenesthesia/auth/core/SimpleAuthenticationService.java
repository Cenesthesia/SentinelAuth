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

//TODO: Можно добавить лимит попыток аутентификации, либо оставить на усмотрение разработчиков

/**
 * Потокобезопасный сервис аутентификации для простых однопользовательских приложений.
 * <p>
 * Предоставляет единую точку входа для операций идентификации, аутентификации и авторизации.
 * Реализован как Singleton для обеспечения глобального доступа из различных частей приложения.
 * </p>
 * <p>
 * <b>Особенности потокобезопасности:</b>
 * </p>
 * <ul>
 *     <li>Использует {@link ReentrantReadWriteLock} для разделения блокировок чтения/записи</li>
 *     <li>Атомарные операции с {@link AtomicReference} для отдельных полей</li>
 *     <li>Иммутабельные возвращаемые значения {@link AuthResult}</li>
 *     <li>Гарантированная очистка чувствительных данных в final-блоках</li>
 * </ul>
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
 * SimpleAuthenticationService.getInstance().setCredentialsProvider(new ConsoleCredentialsProvider());
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
     * @throws NullPointerException если любой из параметров null
     */
    public AuthResult initialize(IAuthUserRepository repository) {
        return initialize(repository, new SimpleAuthenticationProcessor(), new SimpleAuthorizationProcessor());
    }

    /**
     * Инициализирует сервис с репозиторием пользователей кастомным процессором аутентификации ({@link SimpleAuthenticationProcessor}
     *
     * @param repository репозиторий для работы с пользователями
     * @param authenticate кастомный процессор аутентификации
     * @return результат операции инициализации {@link AuthResult}
     * @throws NullPointerException если любой из параметров null
     */
    public AuthResult initialize(IAuthUserRepository repository, IAuthenticationProcessor authenticate) {
        return initialize(repository, authenticate, new SimpleAuthorizationProcessor());
    }

    /**
     * Инициализирует сервис с репозиторием пользователей кастомным процессором авторизации ({@link SimpleAuthorizationProcessor}
     *
     * @param repository репозиторий для работы с пользователями
     * @param authorization кастомный процессор авторизации
     * @return результат операции инициализации {@link AuthResult}
     * @throws NullPointerException если любой из параметров null
     */
    public AuthResult initialize(IAuthUserRepository repository, IAuthorizationProcessor authorization) {
        return initialize(repository, new SimpleAuthenticationProcessor(), authorization);
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
     * @throws  NullPointerException если любой из параметров null
     */
    public AuthResult initialize(IAuthUserRepository repository, IAuthenticationProcessor authenticate,
                                        IAuthorizationProcessor authorization) {
        lock.writeLock().lock();
        try {
            if (isInitialized.get()) {
                if (this.repository == repository &&
                    this.authenticate == authenticate &&
                    this.authorization == authorization) {
                    return AuthResult.success("Service already initialized with same dependencies");
                } else {
                    return AuthResult.failure("Service already initialized with different dependencies");
                }
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
     * Возвращает статус инициализации сервиса аутентификации.
     *
     * @return true, если сервис инициализирован, иначе false
     */
    public boolean isInitialized() {
        return isInitialized.get();
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
     * <p>
     * Может быть вызван как до, так и после инициализации сервиса.
     * Для обычных методов сервиса (не начинающихся с required*) установка не требуется.
     * </p>
     * @param credentialsProvider источник реквизитов
     * @return результат операции установки {@link AuthResult}
     */
    public AuthResult setCredentialsProvider(ICredentialsProvider credentialsProvider) {
        if (credentialsProvider == null) {
            return AuthResult.failure("Credentials provider cannot be null. Credentials provider is not assigned");
        }
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
        principal.clearRoles();
        principal.clearPermission();
    }

    /**
     * Выполняет аутентификацию пользователя по предоставленным реквизитам.
     * <p>
     * <b>Потокобезопасность: </b>использует write lock для изменения состояния аутентификации.
     * </p>
     * @see SimpleAuthenticationService#authenticateWithContext(Credentials, Object)
     *
     * @param credentials реквизиты пользователя
     * @return результат аутентификации {@link AuthResult} с детальной информацией
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
                    return AuthResult.failure("The user was not found in the repository");

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
     * @see SimpleAuthenticationService#requireAuthenticate()
     * @see SimpleAuthenticationService#requireAuthenticateWithContext(Object)
     *
     * @return результат аутентификации {@link AuthResult} с детальной информацией
     */
    public AuthResult requireAuthenticate() {
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
                    return AuthResult.success("Authentication successful");
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
     * @see SimpleAuthenticationService#requireAuthenticate()
     * @see SimpleAuthenticationService#requireAuthenticateWithContext(Object)
     *
     * @param credentials реквизиты аутентификации
     * @param context дополнительный контекст
     * @return результат аутентификации {@link AuthResult} с детальной информацией
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
     * @see SimpleAuthenticationService#authenticateWithContext(Credentials, Object)
     * @see SimpleAuthenticationService#requireAuthenticate()
     *
     * @param context дополнительный контекст
     * @return результат аутентификации {@link AuthResult} с детальной информацией
     */
    public AuthResult requireAuthenticateWithContext(Object context) {
        AuthResult result = requireAuthenticate();
        return result.isSuccess() ?
                result.withMessage("Contextual authentication performed") :
                result.withMessage("Contextual authentication failed");
    }

    /**
     * Завершает сеанс аутентификации пользователя.
     * <p>
     * <b>Потокобезопасность: </b>использует write lock для изменения состояния аутентификации.
     * </p>
     * @see SimpleAuthenticationService#logout(char[])
     *
     * @return результат операции выхода {@link AuthResult} с детальной информацией
     */
    public AuthResult logout() {
        lock.writeLock().lock();
        try {
            AuthResult initCheck = checkInitialization();
            if (!initCheck.isSuccess()) {
                return initCheck;
            }

            if (isAuthenticated.get()) {
                resetState();
                return AuthResult.success("Logout successful");
            }

            resetState();
            return AuthResult.success("No active session - logout operation had no effect");
        } catch (Exception e) {
            return AuthResult.failure(String.format("Unexpected error during logout. Error: %s", e.getMessage()), e);
        } finally {
            lock.writeLock().unlock();
        }
    }

    /**
     * Завершает сеанс аутентификации пользователя по его уникальному идентификатору
     * !!(Наработка на будущее)
     * <p>
     * <b>Потокобезопасность: </b>использует write lock для изменения состояния аутентификации.
     * </p>
     * @see SimpleAuthenticationService#logout()
     *
     * @param id идентификатор пользователя
     * @return результат операции выхода {@link AuthResult} с детальной информацией
     */
    public AuthResult logout(char[] id) {
        lock.writeLock().lock();
        try {
            AuthResult initCheck = checkInitialization();
            if (!initCheck.isSuccess()) {
                return initCheck;
            }

            AuthResult authCheck = checkAuthenticate();
            if (!authCheck.isSuccess()) {
                return authCheck;
            }

            AuthPrincipal currentPrincipal = principal.get();
            if (currentPrincipal != null && Arrays.equals(currentPrincipal.getId(), id)
                || Arrays.equals(currentPrincipal.getUsername(), id)) {
                resetState();
                return AuthResult.success("Logout successful");
            }

            return AuthResult.failure("Session ID does not match current session");
        } catch (Exception e) {
            return AuthResult.failure(String.format("Unexpected error during logout. Error: %s", e.getMessage()), e);
        } finally {
            lock.writeLock().unlock();
        }
    }

    /**
     * Проверяет статус аутентификации текущего пользователя.
     * <p>
     * <b>Потокобезопасность: </b>использует read lock для чтения состояния аутентификации.
     * </p>
     *
     * @return результат проверки статуса аутентификации {@link AuthResult} с детальной информацией
     */
    public AuthResult verifyAuth() {
        lock.readLock().lock();
        try {
            AuthResult initCheck = checkInitialization();
            if (!initCheck.isSuccess()) {
                return initCheck;
            }

            return isAuthenticated.get() ?
                    AuthResult.success("User is authenticated") :
                    AuthResult.failure("User is not authenticated");
        } finally {
            lock.readLock().unlock();
        }
    }

    /**
     * Проверяет наличие роли у аутентифицированного пользователя.
     * <p>
     * <b>Поткобезопасность: </b>использует read lock для чтения данных пользователя.
     * </p>
     * @see SimpleAuthenticationService#hasAllRoles(Collection)
     * @see SimpleAuthenticationService#hasAnyRole(Collection)
     * @see SimpleAuthenticationService#hasAnyRoles(Collection, int)
     * @see SimpleAuthenticationService#hasRoleWithContext(String, Object)
     *
     * @param role проверяемая роль
     * @return результат проверки роли {@link AuthResult} с детальной информацией
     */
    public AuthResult hasRole(String role) {
        lock.readLock().lock();
        try {
            AuthResult initCheck = checkInitialization();
            if (!initCheck.isSuccess()) {
                return initCheck;
            }

            AuthResult authResult = checkAuthenticate();
            if (!authResult.isSuccess()) {
                return authResult;
            }

            AuthResult result = authorization.hasRole(principal.get(), role);
            return result.isSuccess() ?
                    AuthResult.success("User has required role: " + role) :
                    AuthResult.failure("User does not have required role: " + role)
                            .withMessages(result.getMessages())
                            .withExceptions(result.getExceptions());
        } finally {
            lock.readLock().unlock();
        }
    }

    /**
     * Проверяет наличие роли у аутентифицированного пользователя, при необходимости выполняя аутентификацию.
     * <p>
     * <b>ВАЖНО: запрашивает у пользователя роль, но не выполняет аутентификацию (статус не сохраняется)</b>
     * </p>
     * <p>
     * <b>Поткобезопасность: </b>использует read lock, но может временно переходить на write lock для выполнения
     * аутентификации.
     * </p>
     * @see SimpleAuthenticationService#requireAllRoles(Collection)
     * @see SimpleAuthenticationService#requireAnyRole(Collection)
     * @see SimpleAuthenticationService#requireAnyRoles(Collection, int)
     * @see SimpleAuthenticationService#requireRoleWithContext(String, Object)
     *
     * @param role проверяемая роль
     * @return результат проверки роли {@link AuthResult} с детальной информацией
     */
    public AuthResult requireRole(String role) {
        lock.readLock().lock();
        try {
            AuthResult initCheck = checkInitialization();
            if (!initCheck.isSuccess()) {
                return initCheck;
            }

            if (!isAuthenticated.get()) {
                lock.readLock().unlock();
                try {
                    AuthResult authResult = requireAuthenticate();
                    if (!authResult.isSuccess()) {
                        return authResult;
                    }
                } finally {
                    lock.readLock().lock();
                }
            }

            AuthResult result = authorization.hasRole(principal.get(), role);
            lock.readLock().unlock();
            logout();
            lock.readLock().lock();
            return result.isSuccess() ?
                    AuthResult.success("User has required role: " + role) :
                    AuthResult.failure("User does not have required role: " + role)
                            .withMessages(result.getMessages())
                            .withExceptions(result.getExceptions());
        } finally {
            lock.readLock().unlock();
        }
    }

    /**
     * Проверяет наличие всех указанных ролей у аутентифицированного пользователя.
     * <p>
     * <b>Поткобезопасность: </b>использует read lock для чтения данных пользователя.
     * </p>
     * @see SimpleAuthenticationService#hasRole(String)
     * @see SimpleAuthenticationService#hasAnyRole(Collection)
     * @see SimpleAuthenticationService#hasAnyRoles(Collection, int)
     * @see SimpleAuthenticationService#hasRoleWithContext(String, Object)
     *
     * @param roles коллекция проверяемых ролей
     * @return результат проверки ролей {@link AuthResult} с детальной информацией
     */
    public AuthResult hasAllRoles(Collection<String> roles) {
        lock.readLock().lock();
        try {
            AuthResult initCheck = checkInitialization();
            if (!initCheck.isSuccess()) {
                return initCheck;
            }

            AuthResult authCheck = checkAuthenticate();
            if (!authCheck.isSuccess()) {
                return authCheck;
            }

            AuthResult result = authorization.hasAllRoles(principal.get(), roles);
            return result.isSuccess() ?
                    AuthResult.success("User has all required roles") :
                    AuthResult.failure("User does not have all required roles")
                            .withMessages(result.getMessages())
                            .withExceptions(result.getExceptions());
        } finally {
            lock.readLock().unlock();
        }
    }

    /**
     * Проверяет наличие всех указанных ролей у аутентифицированного пользователя, при необходимости выполняя аутентификацию.
     * <p>
     * <b>Поткобезопасность: </b>использует read lock для чтения данных пользователя, может временно переходить на write lock
     * для аутентификации.
     * </p>
     * @see SimpleAuthenticationService#requireRole(String)
     * @see SimpleAuthenticationService#requireAnyRole(Collection)
     * @see SimpleAuthenticationService#requireAnyRoles(Collection, int)
     * @see SimpleAuthenticationService#requireRoleWithContext(String, Object)
     *
     * @param roles коллекция проверяемых ролей
     * @return результат проверки ролей {@link AuthResult} с детальной информацией
     */
    public AuthResult requireAllRoles(Collection<String> roles) {
        lock.readLock().lock();
        try {
            AuthResult initCheck = checkInitialization();
            if (!initCheck.isSuccess()) {
                return initCheck;
            }

            if (!isAuthenticated.get()) {
                lock.readLock().unlock();
                try {
                    AuthResult authResult = requireAuthenticate();
                    if (!authResult.isSuccess()) {
                        return authResult;
                    }
                } finally {
                    lock.readLock().lock();
                }
            }

            AuthResult result = authorization.hasAllRoles(principal.get(), roles);
            return result.isSuccess() ?
                    AuthResult.success("User has all required roles") :
                    AuthResult.failure("User does not have all required roles")
                            .withMessages(result.getMessages())
                            .withExceptions(result.getExceptions());
        } finally {
            lock.readLock().unlock();
        }
    }

    /**
     * Проверяет наличие хотя бы одной роли из {@code roles} у аутентифицированного пользователя.
     * <p>
     * <b>Потокобезопасность: </b>используется read lock для чтения данных пользователя.
     * </p>
     * @see SimpleAuthenticationService#hasRole(String)
     * @see SimpleAuthenticationService#hasAllRoles(Collection)
     * @see SimpleAuthenticationService#hasAnyRoles(Collection, int)
     * @see SimpleAuthenticationService#hasRoleWithContext(String, Object)
     *
     * @param roles коллекция проверяемых ролей
     * @return результат проверки ролей {@link AuthResult} с детальной информацией
     */
    public AuthResult hasAnyRole(Collection<String> roles) {
        lock.readLock().lock();
        try {
            AuthResult initCheck = checkInitialization();
            if (!initCheck.isSuccess()) {
                return initCheck;
            }

            AuthResult authCheck = checkAuthenticate();
            if (!authCheck.isSuccess()) {
                return authCheck;
            }

            AuthResult result = authorization.hasAnyRole(principal.get(), roles);
            return result.isSuccess() ?
                    AuthResult.success("User has at least one required role") :
                    AuthResult.failure("User does not have any of the required roles")
                            .withMessages(result.getMessages())
                            .withExceptions(result.getExceptions());
        } finally {
            lock.readLock().unlock();
        }
    }

    /**
     * Проверяет наличие хотя бы одной роли из {@code roles} у аутентифицированного пользователя, при необходимости выполняя
     * аутентификацию.
     * <p>
     * <b>Потокобезопасность: </b>используется read lock для чтения данных пользователя, может переходить на write lock
     * для аутентификации.
     * </p>
     * @see SimpleAuthenticationService#requireRole(String)
     * @see SimpleAuthenticationService#requireAllRoles(Collection)
     * @see SimpleAuthenticationService#requireAnyRoles(Collection, int)
     * @see SimpleAuthenticationService#requireRoleWithContext(String, Object)
     *
     * @param roles коллекция проверяемых ролей
     * @return результат проверки ролей {@link AuthResult} с детальной информацией
     */
    public AuthResult requireAnyRole(Collection<String> roles) {
        lock.readLock().lock();
        try {
            AuthResult initCheck = checkInitialization();
            if (!initCheck.isSuccess()) {
                return initCheck;
            }

            if (!isAuthenticated.get()) {
                lock.readLock().unlock();
                try {
                    AuthResult authResult = requireAuthenticate();
                    if (!authResult.isSuccess()) {
                        return authResult;
                    }
                } finally {
                    lock.readLock().lock();
                }
            }

            AuthResult result = authorization.hasAnyRole(principal.get(), roles);
            return result.isSuccess() ?
                    AuthResult.success("User has at least one required role") :
                    AuthResult.failure("User does not have any of the required roles")
                            .withMessages(result.getMessages())
                            .withExceptions(result.getExceptions());
        } finally {
            lock.readLock().unlock();
        }
    }

    /**
     * Проверяет наличие хотя бы {@code count} ролей из {@code roles} у аутентифицированного пользователя.
     * <p>
     * <b>Потокобезопасность: </b>используется read lock для чтения данных пользователя.
     * </p>
     * @see SimpleAuthenticationService#hasRole(String)
     * @see SimpleAuthenticationService#hasAllRoles(Collection)
     * @see SimpleAuthenticationService#hasAnyRole(Collection)
     * @see SimpleAuthenticationService#hasRoleWithContext(String, Object)
     *
     * @param roles коллекция проверяемых ролей
     * @param count минимальное количество ролей из списка, которыми должен обладать пользователь
     * @return результат проверки ролей {@link AuthResult} с детальной информацией
     */
    public AuthResult hasAnyRoles(Collection<String> roles, int count) {
        lock.readLock().lock();
        try {
            AuthResult initCheck = checkInitialization();
            if (!initCheck.isSuccess()) {
                return initCheck;
            }

            AuthResult authCheck = checkAuthenticate();
            if (!authCheck.isSuccess()) {
                return  authCheck;
            }

            AuthResult result = authorization.hasAnyRoles(principal.get(), roles, count);
            return result.isSuccess() ?
                    AuthResult.success("User has required number of roles") :
                    AuthResult.failure("User does not have required number of roles")
                            .withMessages(result.getMessages())
                            .withExceptions(result.getExceptions());
        } finally {
            lock.readLock().unlock();
        }
    }

    /**
     * Проверяет наличие хотя бы {@code count} ролей из {@code roles} у аутентифицированного пользователя, при необходимости
     * выполняя аутентификацию.
     * <p>
     * <b>Потокобезопасность: </b>используется read lock для чтения данных пользователя, может переходить на write lock
     * для аутентификации.
     * </p>
     * @see SimpleAuthenticationService#requireRole(String)
     * @see SimpleAuthenticationService#requireAllRoles(Collection)
     * @see SimpleAuthenticationService#requireAnyRole(Collection)
     * @see SimpleAuthenticationService#requireRoleWithContext(String, Object)
     *
     * @param roles коллекция проверяемых ролей
     * @param count минимальное количество ролей из списка, которыми должен обладать пользователь
     * @return результат проверки ролей {@link AuthResult} с детальной информацией
     */
    public AuthResult requireAnyRoles(Collection<String> roles, int count) {
        lock.readLock().lock();
        try {
            AuthResult initCheck = checkInitialization();
            if (!initCheck.isSuccess()) {
                return initCheck;
            }

            if (!isAuthenticated.get()) {
                lock.readLock().unlock();
                try {
                    AuthResult authResult = requireAuthenticate();
                    if (!authResult.isSuccess()) {
                        return authResult;
                    }
                } finally {
                    lock.readLock().lock();
                }
            }

            AuthResult result = authorization.hasAnyRoles(principal.get(), roles, count);
            return result.isSuccess() ?
                    AuthResult.success("User has required number of roles") :
                    AuthResult.failure("User does not have required number of roles")
                            .withMessages(result.getMessages())
                            .withExceptions(result.getExceptions());
        } finally {
            lock.readLock().unlock();
        }
    }

    /**
     * Проверяет наличие права у аутентифицированного пользователя.
     * <p>
     * <b>Потокобезопасность: </b>используется read lock для чтения данных пользователя.
     * </p>
     * @see SimpleAuthenticationService#hasAllPermissions(Collection)
     * @see SimpleAuthenticationService#hasAnyPermission(Collection)
     * @see SimpleAuthenticationService#hasAnyPermissions(Collection, int)
     * @see SimpleAuthenticationService#hasPermissionWithContext(String, Object)
     *
     * @param permission право на проверку
     * @return результат проверки права {@link AuthResult} с детальной информацией
     */
    public AuthResult hasPermission(String permission) {
        lock.readLock().lock();
        try {
            AuthResult initCheck = checkInitialization();
            if (!initCheck.isSuccess()) {
                return initCheck;
            }

            AuthResult authCheck = checkAuthenticate();
            if (!authCheck.isSuccess()) {
                return authCheck;
            }

            AuthResult result = authorization.hasPermission(principal.get(), permission);
            return result.isSuccess() ?
                    AuthResult.success("User has required permission: " + permission) :
                    AuthResult.failure("User does not have required permission: " + permission)
                            .withMessages(result.getMessages())
                            .withExceptions(result.getExceptions());
        } finally {
            lock.readLock().unlock();
        }
    }

    /**
     * Проверяет наличие права у аутентифицированного пользователя, при необходимости выполняя аутентификацию.
     * <p>
     * <b>Поткобезопасность: </b>использует read lock для чтения данных пользователя, но может временно переходить на
     * write lock для выполнения аутентификации.
     * </p>
     * @see SimpleAuthenticationService#requireAllPermissions(Collection)
     * @see SimpleAuthenticationService#requireAnyPermission(Collection) (Collection)
     * @see SimpleAuthenticationService#requireAnyPermissions(Collection, int) (Collection, int)
     * @see SimpleAuthenticationService#requirePermissionWithContext(String, Object)
     *
     * @param permission право на проверку
     * @return результат проверки права {@link AuthResult} с детальной информацией
     */
    public AuthResult requirePermission(String permission) {
        lock.readLock().lock();
        try {
            AuthResult initCheck = checkInitialization();
            if (!initCheck.isSuccess()) {
                return initCheck;
            }

            if (!isAuthenticated.get()) {
                lock.readLock().unlock();
                try {
                    AuthResult authResult = requireAuthenticate();
                    if (!authResult.isSuccess()) {
                        return authResult;
                    }
                } finally {
                    lock.readLock().lock();
                }
            }

            AuthResult result = authorization.hasPermission(principal.get(), permission);
            return result.isSuccess() ?
                    AuthResult.success("User has required permission: " + permission) :
                    AuthResult.failure("User does not have required permission: " + permission)
                            .withMessages(result.getMessages())
                            .withExceptions(result.getExceptions());
        } finally {
            lock.readLock().unlock();
        }
    }

    /**
     * Проверяет наличие всех указанных прав у аутентифицированного пользователя.
     * <p>
     * <b>Потокобезопасность: </b>используется read lock для чтения данных пользователя.
     * </p>
     * @see SimpleAuthenticationService#hasPermission(String)
     * @see SimpleAuthenticationService#hasAnyPermission(Collection)
     * @see SimpleAuthenticationService#hasAnyPermissions(Collection, int)
     * @see SimpleAuthenticationService#hasPermissionWithContext(String, Object)
     *
     * @param permissions коллекция прав на проверку
     * @return результат проверки прав {@link AuthResult} с детальной информацией
     */
    public AuthResult hasAllPermissions(Collection<String> permissions) {
        lock.readLock().lock();
        try {
            AuthResult initCheck = checkInitialization();
            if (!initCheck.isSuccess()) {
                return initCheck;
            }

            AuthResult authCheck = checkAuthenticate();
            if (!authCheck.isSuccess()) {
                return authCheck;
            }

            AuthResult result = authorization.hasAllPermissions(principal.get(), permissions);
            return result.isSuccess() ?
                    AuthResult.success("User has all required permissions") :
                    AuthResult.failure("User does not have all required permissions")
                            .withMessages(result.getMessages())
                            .withExceptions(result.getExceptions());
        } finally {
            lock.readLock().unlock();
        }
    }

    /**
     * Проверяет наличие всех указанных прав у аутентифицированного пользователя, при необходимости выполняя аутентификацию.
     * <p>
     * <b>Потокобезопасность: </b>используется read lock для чтения данных пользователя, но может временно переходить на
     * write lock для выполнения аутентификации.
     * </p>
     * @see SimpleAuthenticationService#requirePermission(String)
     * @see SimpleAuthenticationService#requireAnyPermission(Collection)
     * @see SimpleAuthenticationService#requireAnyPermissions(Collection, int)
     * @see SimpleAuthenticationService#requirePermissionWithContext(String, Object)
     *
     * @param permissions коллекция прав на проверку
     * @return результат проверки прав {@link AuthResult} с детальной информацией
     */
    public AuthResult requireAllPermissions(Collection<String> permissions) {
        lock.readLock().lock();
        try {
            AuthResult initCheck = checkInitialization();
            if (!initCheck.isSuccess()) {
                return initCheck;
            }

            if (!isAuthenticated.get()) {
                lock.readLock().unlock();
                try {
                    AuthResult authResult = requireAuthenticate();
                    if (!authResult.isSuccess()) {
                        return authResult;
                    }
                } finally {
                    lock.readLock().lock();
                }
            }

            AuthResult result = authorization.hasAllPermissions(principal.get(), permissions);
            return result.isSuccess() ?
                    AuthResult.success("User has all required permissions") :
                    AuthResult.failure("User does not have all required permissions")
                            .withMessages(result.getMessages())
                            .withExceptions(result.getExceptions());
        } finally {
            lock.readLock().unlock();
        }
    }

    /**
     * Проверяет наличие хотя бы одного права из {@code permissions} у аутентифицированного пользователя.
     * <p>
     * <b>Потокобезопасность: </b>используется read lock для чтения данных пользователя.
     * </p>
     * @see SimpleAuthenticationService#hasPermission(String)
     * @see SimpleAuthenticationService#hasAllPermissions(Collection)
     * @see SimpleAuthenticationService#hasAnyPermissions(Collection, int)
     * @see SimpleAuthenticationService#hasPermissionWithContext(String, Object)
     *
     * @param permissions коллекция прав на проверку
     * @return результат проверки прав {@link AuthResult} с детальной информацией
     */
    public AuthResult hasAnyPermission(Collection<String> permissions) {
        lock.readLock().lock();
        try {
            AuthResult initCheck = checkInitialization();
            if (!initCheck.isSuccess()) {
                return initCheck;
            }

            AuthResult authCheck = checkAuthenticate();
            if (!authCheck.isSuccess()) {
                return authCheck;
            }

            AuthResult result = authorization.hasAnyPermission(principal.get(), permissions);
            return result.isSuccess() ?
                    AuthResult.success("User has at least one required permission") :
                    AuthResult.failure("User does not have any of the required permissions")
                            .withMessages(result.getMessages())
                            .withExceptions(result.getExceptions());
        } finally {
            lock.readLock().unlock();
        }
    }

    /**
     * Проверяет наличие хотя бы одного права из {@code permissions} у аутентифицированного пользователя, при необходимости
     * выполняя аутентификацию.
     * <p>
     * <b>Потокобезопасность: </b>используется read lock для чтения данных пользователя, но может временно переходить на
     * write lock для выполнения аутентификации.
     * </p>
     * @see SimpleAuthenticationService#requirePermission(String)
     * @see SimpleAuthenticationService#requireAllPermissions(Collection)
     * @see SimpleAuthenticationService#requireAnyPermissions(Collection, int)
     * @see SimpleAuthenticationService#requirePermissionWithContext(String, Object)
     *
     * @param permissions коллекция прав на проверку
     * @return результат проверки прав {@link AuthResult} с детальной информацией
     */
    public AuthResult requireAnyPermission(Collection<String> permissions) {
        lock.readLock().lock();
        try {
            AuthResult initCheck = checkInitialization();
            if (!initCheck.isSuccess()) {
                return initCheck;
            }

            if (!isAuthenticated.get()) {
                lock.readLock().unlock();
                try {
                    AuthResult authResult = requireAuthenticate();
                    if (!authResult.isSuccess()) {
                        return authResult;
                    }
                } finally {
                    lock.readLock().lock();
                }
            }

            AuthResult result = authorization.hasAnyPermission(principal.get(), permissions);
            return result.isSuccess() ?
                    AuthResult.success("User has at least one required permission") :
                    AuthResult.failure("User does not have any of the required permissions")
                            .withMessages(result.getMessages())
                            .withExceptions(result.getExceptions());
        } finally {
            lock.readLock().unlock();
        }
    }

    /**
     * Проверяет наличие хотя бы {@code count} прав у аутентифицированного пользователя из {@code permissions}
     * <p>
     * <b>Потокобезопасность: </b>используется read lock для чтения данных пользователя.
     * </p>
     * @see SimpleAuthenticationService#hasPermission(String)
     * @see SimpleAuthenticationService#hasAllPermissions(Collection)
     * @see SimpleAuthenticationService#hasAnyPermission(Collection)
     * @see SimpleAuthenticationService#hasPermissionWithContext(String, Object)
     *
     * @param permissions права на проверку
     * @param count минимальное количество прав из списка, которыми должен обладать пользователь
     * @return результат проверки прав {@link AuthResult} с детальной информацией
     */
    public AuthResult hasAnyPermissions(Collection<String> permissions, int count) {
        lock.readLock().lock();
        try {
            AuthResult initCheck = checkInitialization();
            if (!initCheck.isSuccess()) {
                return initCheck;
            }

            AuthResult authCheck = checkAuthenticate();
            if (!authCheck.isSuccess()) {
                return authCheck;
            }

            AuthResult result = authorization.hasAnyPermissions(principal.get(), permissions, count);
            return result.isSuccess() ?
                    AuthResult.success("User has required number of permissions") :
                    AuthResult.failure("User does not have required number of permissions")
                            .withMessages(result.getMessages())
                            .withExceptions(result.getExceptions());
        } finally {
            lock.readLock().unlock();
        }
    }

    /**
     * Проверяет наличие хотя бы {@code count} прав у аутентифицированного пользователя из {@code permissions}, при
     * необходимости выполняя аутентификацию.
     * <p>
     * <b>Потокобезопасность: </b>используется read lock для чтения данных пользователя, но может временно переходить на
     * write lock для выполнения аутентификации.
     * </p>
     * @see SimpleAuthenticationService#requirePermission(String)
     * @see SimpleAuthenticationService#requireAllPermissions(Collection)
     * @see SimpleAuthenticationService#requireAnyPermission(Collection)
     * @see SimpleAuthenticationService#requirePermissionWithContext(String, Object)
     *
     * @param permissions права на проверку
     * @param count минимальное количество прав из списка, которыми должен обладать пользователь
     * @return результат проверки прав {@link AuthResult} с детальной информацией
     */
    public AuthResult requireAnyPermissions(Collection<String> permissions, int count) {
        lock.readLock().lock();
        try {
            AuthResult initCheck = checkInitialization();
            if (!initCheck.isSuccess()) {
                return initCheck;
            }

            if (!isAuthenticated.get()) {
                lock.readLock().unlock();
                try {
                    AuthResult authResult = requireAuthenticate();
                    if (!authResult.isSuccess()) {
                        return authResult;
                    }
                } finally {
                    lock.readLock().lock();
                }
            }

            AuthResult result = authorization.hasAnyPermissions(principal.get(), permissions, count);
            return result.isSuccess() ?
                    AuthResult.success("User has required number of permissions") :
                    AuthResult.failure("User does not have required number of permissions")
                            .withMessages(result.getMessages())
                            .withExceptions(result.getExceptions());
        } finally {
            lock.readLock().unlock();
        }
    }

    /**
     * Проверяет наличие у пользователя роли с дополнительной контекстной информацией.
     * Заделка для кастомных авторизационных сервисов. По умолчанию делегирует вызов методу {@link SimpleAuthenticationService#hasRole(String)}.
     * <p>
     * <b>Потокобезопасность: </b>используется read lock для чтения данных пользователя.
     * </p>
     * @see SimpleAuthenticationService#hasRole(String)
     * @see SimpleAuthenticationService#hasAllRoles(Collection)
     * @see SimpleAuthenticationService#hasAnyRole(Collection)
     * @see SimpleAuthenticationService#hasAnyRoles(Collection, int)
     *
     * @param role проверяемая роль
     * @param context контекст
     * @return результат проверки роли {@link AuthResult} с детальной информацией
     */
    public AuthResult hasRoleWithContext(String role, Object context) {
        AuthResult result = hasRole(role);
        return result.isSuccess() ?
                result.withMessage("Contextual role check performed") :
                result.withMessage("Contextual role check failed");
    }

    /**
     * Проверяет наличие у пользователя роли с дополнительной контекстной информацией, при необходимости выполняя аутентификацию.
     * Заделка для кастомных авторизационных сервисов. По умолчанию делегирует вызов методу {@link SimpleAuthenticationService#requireRole(String)}.
     * <p>
     * <b>Потокобезопасность: </b>используется read lock для чтения данных пользователя, но может временно переходить на
     * write lock для выполнения аутентификации.
     * </p>
     * @see SimpleAuthenticationService#requireRole(String)
     * @see SimpleAuthenticationService#requireAllRoles(Collection)
     * @see SimpleAuthenticationService#requireAnyRole(Collection)
     * @see SimpleAuthenticationService#requireAnyRoles(Collection, int)
     *
     * @param role проверяемая роль
     * @param context контекст
     * @return результат проверки роли {@link AuthResult} с детальной информацией
     */
    public AuthResult requireRoleWithContext(String role, Object context) {
        AuthResult result = requireRole(role);
        return result.isSuccess() ?
                result.withMessage("Contextual role check performed") :
                result.withMessage("Contextual role check failed");
    }

    /**
     * Проверяет наличие права у пользователя с дополнительной контекстной информацией.
     * Заделка для кастомных авторизационных сервисов. По умолчанию делегирует вызов методу {@link SimpleAuthenticationService#hasPermission(String)}.
     * <p>
     * <b>Потокобезопасность: </b>используется read lock для чтения данных пользователя.
     * </p>
     * @see SimpleAuthenticationService#hasPermission(String)
     * @see SimpleAuthenticationService#hasAllPermissions(Collection)
     * @see SimpleAuthenticationService#hasAnyPermission(Collection)
     * @see SimpleAuthenticationService#hasAnyPermissions(Collection, int)
     *
     * @param permission право на проверку
     * @param context контекст
     * @return результат проверки права {@link AuthResult} с детальной информацией
     */
    public AuthResult hasPermissionWithContext(String permission, Object context) {
        AuthResult result = hasPermission(permission);
        return result.isSuccess() ?
                result.withMessage("Contextual permission check performed") :
                result.withMessage("Contextual permission check failed");
    }

    /**
     * Проверяет наличие права у пользователя с дополнительной контекстной информацией, при необходимости выполняя аутентификацию.
     * Заделка для кастомных авторизационных сервисов. По умолчанию делегирует вызов методу {@link SimpleAuthenticationService#requirePermission(String)}.
     * <p>
     * <b>Потокобезопасность: </b>используется read lock для чтения данных пользователя, но может временно переходить на
     * write lock для выполнения аутентификации.
     * </p>
     * @see SimpleAuthenticationService#requirePermission(String)
     * @see SimpleAuthenticationService#requireAllPermissions(Collection)
     * @see SimpleAuthenticationService#requireAnyPermission(Collection)
     * @see SimpleAuthenticationService#requireAnyPermissions(Collection, int)
     *
     * @param permission право на проверку
     * @param context контекст
     * @return результат проверки права {@link AuthResult} с детальной информацией
     */
    public AuthResult requirePermissionWithContext(String permission, Object context) {
        AuthResult result = requirePermission(permission);
        return result.isSuccess() ?
                result.withMessage("Contextual permission check performed") :
                result.withMessage("Contextual permission check failed");
    }

    /**
     * Возвращает уникальный идентификатор аутентифицированного пользователя в безопасном виде.
     * <p>
     * <b>Потокобезопасность: </b>использует read lock для чтения данных пользователя.
     * </p>
     *
     * @return Optional с копией идентификатора пользователя или empty Optional
     */
    public Optional<String> getCurrentUserId() {
        lock.readLock().lock();
        try {
            AuthPrincipal current = principal.get();
            if (current != null && current.getId() != null) {
                return Optional.of(new String(current.getId()));
            }
            return Optional.empty();
        } finally {
            lock.readLock().unlock();
        }
    }

    /**
     * Возвращает имя текущего аутентифицированного пользователя в безопасном виде.
     * <p>
     * <b>Потокобезопасность: </b>использует read lock для чтения данных пользователя.
     * </p>
     *
     * @return Optional с копией имени пользователя или empty Optional
     */
    public Optional<String> getCurrentUsername() {
        lock.readLock().lock();
        try {
            AuthPrincipal current = principal.get();
            if (current != null && current.getUsername() != null) {
                return Optional.of(new String(current.getUsername()));
            }
            return Optional.empty();
        } finally {
            lock.readLock().unlock();
        }
    }
}
