package com.cenesthesia.auth.services;

import com.cenesthesia.auth.api.IAuthUserRepository;
import com.cenesthesia.auth.api.IAuthenticationProcessor;
import com.cenesthesia.auth.api.IAuthorizationProcessor;
import com.cenesthesia.auth.api.ICredentialsProvider;
import com.cenesthesia.auth.common.AuthPrincipal;
import com.cenesthesia.auth.common.AuthResult;
import com.cenesthesia.auth.common.Credentials;
import com.cenesthesia.auth.core.SimpleAuthenticationProcessor;
import com.cenesthesia.auth.core.SimpleAuthenticationService;
import com.cenesthesia.auth.core.SimpleAuthorizationProcessor;
import org.junit.jupiter.api.*;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;
import org.mockito.MockedStatic;
import static org.mockito.Mockito.*;

import java.lang.reflect.Field;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

@Tag("unit")
@Execution(ExecutionMode.SAME_THREAD)
public class SimpleAuthenticationServiceTest {
    private SimpleAuthenticationService authService;
    private IAuthUserRepository userRepository;
    private IAuthenticationProcessor authProcessor;
    private IAuthorizationProcessor authzProcessor;
    private ICredentialsProvider credentialsProvider;
    private AuthPrincipal testPrincipal;
    private Credentials testCredentials;
    private MockedStatic<SimpleAuthenticationService> mockedStatic;

    private void resetSingletonInstance() throws Exception {
        Field instanceField = SimpleAuthenticationService.class.getDeclaredField("INSTANCE");
        instanceField.setAccessible(true);
        instanceField.set(null, null);
        SimpleAuthenticationService existingInstance = SimpleAuthenticationService.getInstance();
        if (existingInstance != null) {
            resetServiceState(existingInstance);
        }
    }

    private void resetServiceState(SimpleAuthenticationService service) throws Exception {
        Field isInitializedField = SimpleAuthenticationService.class.getDeclaredField("isInitialized");
        isInitializedField.setAccessible(true);
        @SuppressWarnings("unchecked")
        AtomicReference<Boolean> isInitialized = (AtomicReference<Boolean>) isInitializedField.get(service);
        isInitialized.set(false);

        Field isAuthenticatedField = SimpleAuthenticationService.class.getDeclaredField("isAuthenticated");
        isAuthenticatedField.setAccessible(true);
        @SuppressWarnings("unchecked")
        AtomicReference<Boolean> isAuthenticated = (AtomicReference<Boolean>) isAuthenticatedField.get(service);

        Field principalField = SimpleAuthenticationService.class.getDeclaredField("principal");
        principalField.setAccessible(true);
        @SuppressWarnings("unchecked")
        AtomicReference<AuthPrincipal> principal = (AtomicReference<AuthPrincipal>) principalField.get(service);

        Field credentialsProviderField = SimpleAuthenticationService.class.getDeclaredField("credentialsProvider");
        credentialsProviderField.setAccessible(true);
        @SuppressWarnings("unchecked")
        AtomicReference<ICredentialsProvider> credentialsProvider =
                (AtomicReference<ICredentialsProvider>) credentialsProviderField.get(service);

        Field repositoryField = SimpleAuthenticationService.class.getDeclaredField("repository");
        repositoryField.setAccessible(true);
        repositoryField.set(service, null);

        Field authProcessorField = SimpleAuthenticationService.class.getDeclaredField("authenticate");
        authProcessorField.setAccessible(true);
        authProcessorField.set(service, null);

        Field authzProcessorField = SimpleAuthenticationService.class.getDeclaredField("authorization");
        authzProcessorField.setAccessible(true);
        authzProcessorField.set(service, null);
    }

    private SimpleAuthenticationService createFreshServiceInstance() throws Exception {
        resetSingletonInstance();
        return SimpleAuthenticationService.getInstance();
    }

    @BeforeEach
    void setUp() throws Exception {
        resetSingletonInstance();
        authService = SimpleAuthenticationService.getInstance();

        userRepository = mock(IAuthUserRepository.class);
        authProcessor = mock(IAuthenticationProcessor.class);
        authzProcessor = mock(IAuthorizationProcessor.class);
        credentialsProvider = mock(ICredentialsProvider.class);

        testPrincipal = new AuthPrincipal("1".toCharArray(), "testUser".toCharArray());
        testCredentials = new Credentials("testUser".toCharArray(), "testPassword".toCharArray());

        AuthResult initResult = authService.initialize(userRepository, authProcessor, authzProcessor);
        assertTrue(initResult.isSuccess());
    }

    @AfterEach
    void tearDown() throws Exception {
        resetSingletonInstance();
    }

    //======================================= initialize tests ============================================

    @Test
    @DisplayName("initialize should return successful AuthResult when all dependencies are valid")
    void initializeWhenAllDependenciesAreValid() throws Exception {
        authService = createFreshServiceInstance();
        AuthResult result = authService.initialize(userRepository, authProcessor, authzProcessor);

        assertTrue(result.isSuccess());
        assertTrue(result.hasMessages());
        assertEquals("Service initialized successfully", result.getMessages().get(0));
    }

    @Test
    @DisplayName("initialize should return failed AuthResult when userRepository is null")
    void initializeWhenUserRepositoryIsNull() throws Exception {
        authService = createFreshServiceInstance();
        AuthResult result = authService.initialize(null, authProcessor, authzProcessor);

        assertFalse(result.isSuccess());
        assertTrue(result.hasMessages());
        assertEquals("Initialization failed", result.getMessages().get(0));
        assertTrue(result.hasExceptions());
        assertEquals("Initialize error: user repository cannot be null", result.getExceptions().get(0).getMessage());
    }

    @Test
    @DisplayName("initialize should return failed AuthResult when authProcessor is null")
    void initializeWhenAuthenticationProcessorIsNull() throws Exception {
        authService = createFreshServiceInstance();
        AuthResult result = authService.initialize(userRepository, null, authzProcessor);

        assertFalse(result.isSuccess());
        assertTrue(result.hasMessages());
        assertEquals("Initialization failed", result.getMessages().get(0));
        assertTrue(result.hasExceptions());
        assertEquals("Initialize error: authenticate processor cannot be null", result.getExceptions().get(0).getMessage());
    }

    @Test
    @DisplayName("initialize should return failed AuthResult when authzProcessor is null")
    void initializeWhenAuthorizationProcessorIsNull() throws Exception {
        authService = createFreshServiceInstance();
        AuthResult result = authService.initialize(userRepository, authProcessor, null);

        assertFalse(result.isSuccess());
        assertTrue(result.hasMessages());
        assertEquals("Initialization failed", result.getMessages().get(0));
        assertTrue(result.hasExceptions());
        assertEquals("Initialize error: authorization processor cannot be null", result.getExceptions().get(0).getMessage());
    }

    @Test
    @DisplayName("initialize should return successful AuthResult when the service is reinitialized with the same dependencies")
    void initializeWhenServiceAlreadyInitializedSame() throws Exception {
        AuthResult result = authService.initialize(userRepository, authProcessor, authzProcessor);

        assertTrue(result.isSuccess());
        assertTrue(result.hasMessages());
        assertEquals("Service already initialized with same dependencies", result.getMessages().get(0));
    }

    @Test
    @DisplayName("initialize should return successful AuthResult when the service is reinitialized with the different dependencies")
    void initializeWhenServiceAlreadyInitializedDifferent() throws Exception {
        AuthResult result = authService.initialize(userRepository, new SimpleAuthenticationProcessor(), new SimpleAuthorizationProcessor());

        assertFalse(result.isSuccess());
        assertTrue(result.hasMessages());
        assertEquals("Service already initialized with different dependencies", result.getMessages().get(0));
    }

    //======================================== getInstance tests =============================================

    @Test
    @DisplayName("getInstance should return same instance on multiple calls")
    void getInstanceShouldReturnSameInstance() {
        SimpleAuthenticationService instance1 = SimpleAuthenticationService.getInstance();
        SimpleAuthenticationService instance2 = SimpleAuthenticationService.getInstance();
        assertSame(instance1, instance2, "getInstance should return the same instance");
    }

    //=================================== setCredentialsProvider tests ========================================

    @Test
    @DisplayName("setCredentialsProvider should return successful AuthResult when credentials provider correct")
    void setCredentialsProviderWhenCredentialsProviderIsCorrect() {
        AuthResult result = authService.setCredentialsProvider(credentialsProvider);

        assertTrue(result.isSuccess());
        assertTrue(result.hasMessages());
        assertEquals("Credentials provider set successfully", result.getMessages().get(0));
    }

    @Test
    @DisplayName("setCredentialsProvider should return failed AuthResult when credentials provider is null")
    void setCredentialsProviderWhenCredentialsProviderIsNull() {
        AuthResult result = authService.setCredentialsProvider(null);

        assertFalse(result.isSuccess());
        assertTrue(result.hasMessages());
        assertEquals("Credentials provider cannot be null. Credentials provider is not assigned",
                result.getMessages().get(0));
    }

    //======================================== authenticate tests =============================================

    @Test
    @DisplayName("authenticate should return successful AuthResult when credentials are valid")
    void authenticateWhenCredentialsAreValid() {
        when(userRepository.findByUsername("testUser")).thenReturn(Optional.of(testPrincipal));
        when(authProcessor.authenticate(eq(testPrincipal), any(Credentials.class)))
                .thenReturn(AuthResult.success("Authentication successful"));

        AuthResult result = authService.authenticate(testCredentials);

        assertTrue(result.isSuccess());
        assertTrue(result.hasMessages());
        assertEquals("Authenticate successful", result.getMessages().get(0));
        verify(userRepository).findByUsername("testUser");
        verify(authProcessor).authenticate(eq(testPrincipal), any(Credentials.class));
        assertTrue(authService.getCurrentUsername().isPresent());

        AuthResult resultVerify = authService.verifyAuth();
        assertTrue(resultVerify.isSuccess());
        assertTrue(resultVerify.hasMessages());
        assertEquals("User is authenticated", resultVerify.getMessages().get(0));
    }

    @Test
    @DisplayName("authenticate should return failed AuthResult when user not found in repository")
    void authenticateWhenUserNotFound() {
        when(userRepository.findByUsername("testUser")).thenReturn(Optional.empty());

        AuthResult result = authService.authenticate(testCredentials);

        assertFalse(result.isSuccess());
        assertTrue(result.hasMessages());
        assertEquals("The user was not found in the repository", result.getMessages().get(0));
        verify(userRepository).findByUsername("testUser");
        assertTrue(authService.getCurrentUsername().isEmpty());

        AuthResult resultVerify = authService.verifyAuth();
        assertFalse(resultVerify.isSuccess());
        assertTrue(resultVerify.hasMessages());
        assertEquals("User is not authenticated", resultVerify.getMessages().get(0));
    }

    @Test
    @DisplayName("authenticate should return failed AuthResult when authentication processor returns failure")
    void authenticateWhenAuthenticationFails() {
        when(userRepository.findByUsername("testUser")).thenReturn(Optional.of(testPrincipal));
        when(authProcessor.authenticate(eq(testPrincipal), any(Credentials.class))).thenReturn(AuthResult.failure("Invalid credentials"));

        AuthResult result = authService.authenticate(testCredentials);

        assertFalse(result.isSuccess());
        assertTrue(result.hasMessages());
        assertEquals("Authenticate failed - invalid credentials", result.getMessages().get(0));
        verify(userRepository).findByUsername("testUser");
        verify(authProcessor).authenticate(eq(testPrincipal), any(Credentials.class));
        assertTrue(authService.getCurrentUsername().isEmpty());

        AuthResult resultVerify = authService.verifyAuth();
        assertFalse(resultVerify.isSuccess());
        assertTrue(resultVerify.hasMessages());
        assertEquals("User is not authenticated", resultVerify.getMessages().get(0));
    }

    @Test
    @DisplayName("authenticate should return failed AuthResult when service not initialized")
    void authenticateWhenServiceNotInitialized() throws Exception {
        authService = createFreshServiceInstance();

        AuthResult result = authService.authenticate(testCredentials);

        assertFalse(result.isSuccess());
        assertTrue(result.hasMessages());
        assertEquals("SimpleAuthenticationService not initialized. Call initialize() before using",
                result.getMessages().get(0));
        assertTrue(authService.getCurrentUsername().isEmpty());
    }

    @Test
    @DisplayName("authenticate should return failed AuthResult when user repository throws exception")
    void authenticateWhenUserRepositoryThrowsException() {
        when(userRepository.findByUsername(any(String.class))).thenThrow(
                new RuntimeException("authenticate error"));

        AuthResult result = authService.authenticate(testCredentials);

        assertFalse(result.isSuccess());
        assertTrue(result.hasMessages());
        assertTrue(result.hasExceptions());
        assertEquals("Authentication error: authenticate error", result.getMessages().get(0));
        assertInstanceOf(RuntimeException.class, result.getExceptions().get(0));
        assertEquals("authenticate error", result.getExceptions().get(0).getMessage());
        assertTrue(authService.getCurrentUsername().isEmpty());

        AuthResult resultVerify = authService.verifyAuth();
        assertFalse(resultVerify.isSuccess());
        assertTrue(resultVerify.hasMessages());
        assertEquals("User is not authenticated", resultVerify.getMessages().get(0));
    }

    @Test
    @DisplayName("authenticate should return failed AuthResult when authenticate processor throws exception")
    void authenticateWhenAuthenticateProcessorThrowsException() throws NoSuchMethodException {
        when(userRepository.findByUsername("testUser")).thenReturn(Optional.of(testPrincipal));
        when(authProcessor.authenticate(eq(testPrincipal), any(Credentials.class))).thenThrow(
                new RuntimeException("authenticate error"));

        AuthResult result = authService.authenticate(testCredentials);

        assertFalse(result.isSuccess());
        assertTrue(result.hasMessages());
        assertTrue(result.hasExceptions());
        assertEquals("Authentication error: authenticate error", result.getMessages().get(0));
        assertInstanceOf(RuntimeException.class, result.getExceptions().get(0));
        assertEquals("authenticate error", result.getExceptions().get(0).getMessage());
        assertTrue(authService.getCurrentUsername().isEmpty());

        AuthResult resultVerify = authService.verifyAuth();
        assertFalse(resultVerify.isSuccess());
        assertTrue(resultVerify.hasMessages());
        assertEquals("User is not authenticated", resultVerify.getMessages().get(0));
    }

    //==================================== requireAuthenticate tests ==========================================

    @Test
    @DisplayName("requireAuthenticate should return successful when credentials provider returns valid credentials")
    void requireAuthenticateWhenCredentialsAreValid() {
        AuthResult setResult = authService.setCredentialsProvider(credentialsProvider);
        assertTrue(setResult.isSuccess());
        when(credentialsProvider.provideCredentials()).thenReturn(testCredentials);
        when(userRepository.findByUsername("testUser")).thenReturn(Optional.of(testPrincipal));
        when(authProcessor.authenticate(eq(testPrincipal), eq(testCredentials)))
                .thenReturn(AuthResult.success("Authentication successful"));

        AuthResult result = authService.requireAuthenticate();

        assertTrue(result.isSuccess());
        assertTrue(result.hasMessages());
        assertEquals("Authentication successful", result.getMessages().get(0));
        verify(credentialsProvider).provideCredentials();
        verify(userRepository).findByUsername("testUser");
        verify(authProcessor).authenticate(eq(testPrincipal), eq(testCredentials));
        assertTrue(authService.getCurrentUsername().isPresent());

        AuthResult resultVerify = authService.verifyAuth();
        assertTrue(resultVerify.isSuccess());
        assertTrue(resultVerify.hasMessages());
        assertEquals("User is authenticated", resultVerify.getMessages().get(0));
    }

    @Test
    @DisplayName("requireAuthenticate should return failed AuthResult when service not initialized")
    void requireAuthenticateWhenServiceNotInitialized() throws Exception {
        authService = createFreshServiceInstance();

        AuthResult result = authService.requireAuthenticate();

        assertFalse(result.isSuccess());
        assertTrue(result.hasMessages());
        assertEquals("SimpleAuthenticationService not initialized. Call initialize() before using",
                result.getMessages().get(0));
        assertTrue(authService.getCurrentUsername().isEmpty());
    }

    @Test
    @DisplayName("requireAuthenticate should return failed AuthResult when credentials provider not set")
    void requireAuthenticateWhenCredentialsProviderNotSet() {
        AuthResult result = authService.requireAuthenticate();

        assertFalse(result.isSuccess());
        assertTrue(result.hasMessages());
        assertEquals("Source of credentials not specified. Call setCredentialsProvider() before using",
                result.getMessages().get(0));
        assertTrue(authService.getCurrentUsername().isEmpty());

        AuthResult resultVerify = authService.verifyAuth();
        assertFalse(resultVerify.isSuccess());
        assertTrue(resultVerify.hasMessages());
        assertEquals("User is not authenticated", resultVerify.getMessages().get(0));
    }

    @Test
    @DisplayName("requireAuthenticate should return failed AuthResult when credentials provider throws exception")
    void requireAuthenticateWhenCredentialsProviderThrowException() {
        authService.setCredentialsProvider(credentialsProvider);
        when(credentialsProvider.provideCredentials()).thenThrow(new RuntimeException("Provider error"));

        AuthResult result = authService.requireAuthenticate();

        assertFalse(result.isSuccess());
        assertTrue(result.hasMessages());
        assertTrue(result.hasExceptions());
        assertEquals("Failed to obtain credentials. Exception: Provider error", result.getMessages().get(0));
        assertInstanceOf(RuntimeException.class, result.getExceptions().get(0));
        assertEquals("Provider error", result.getExceptions().get(0).getMessage());
        assertTrue(authService.getCurrentUsername().isEmpty());

        AuthResult resultVerify = authService.verifyAuth();
        assertFalse(resultVerify.isSuccess());
        assertTrue(resultVerify.hasMessages());
        assertEquals("User is not authenticated", resultVerify.getMessages().get(0));
    }

    @Test
    @DisplayName("requireAuthenticate should return failed AuthResult when user repository throws exception")
    void requireAuthenticateWhenUserRepositoryThrowsException() {
        authService.setCredentialsProvider(credentialsProvider);
        when(credentialsProvider.provideCredentials()).thenReturn(testCredentials);
        when(userRepository.findByUsername(any(String.class))).thenThrow(
                new RuntimeException("authenticate error"));

        AuthResult result = authService.requireAuthenticate();

        assertFalse(result.isSuccess());
        assertTrue(result.hasMessages());
        assertTrue(result.hasExceptions());
        assertEquals("Authentication error: authenticate error", result.getMessages().get(0));
        assertInstanceOf(RuntimeException.class, result.getExceptions().get(0));
        assertEquals("authenticate error", result.getExceptions().get(0).getMessage());
        assertTrue(authService.getCurrentUsername().isEmpty());

        AuthResult resultVerify = authService.verifyAuth();
        assertFalse(resultVerify.isSuccess());
        assertTrue(resultVerify.hasMessages());
        assertEquals("User is not authenticated", resultVerify.getMessages().get(0));
    }

    @Test
    @DisplayName("requireAuthenticate should return failed AuthResult when authenticate processor throws exception")
    void requireAuthenticateWhenAuthenticateProcessorThrowsException() throws NoSuchMethodException {
        authService.setCredentialsProvider(credentialsProvider);
        when(credentialsProvider.provideCredentials()).thenReturn(testCredentials);
        when(userRepository.findByUsername("testUser")).thenReturn(Optional.of(testPrincipal));
        when(authProcessor.authenticate(eq(testPrincipal), any(Credentials.class))).thenThrow(
                new RuntimeException("authenticate error"));

        AuthResult result = authService.requireAuthenticate();

        assertFalse(result.isSuccess());
        assertTrue(result.hasMessages());
        assertTrue(result.hasExceptions());
        assertEquals("Authentication error: authenticate error", result.getMessages().get(0));
        assertInstanceOf(RuntimeException.class, result.getExceptions().get(0));
        assertEquals("authenticate error", result.getExceptions().get(0).getMessage());
        assertTrue(authService.getCurrentUsername().isEmpty());

        AuthResult resultVerify = authService.verifyAuth();
        assertFalse(resultVerify.isSuccess());
        assertTrue(resultVerify.hasMessages());
        assertEquals("User is not authenticated", resultVerify.getMessages().get(0));
    }

    //========================================== logout tests =================================================

    @Test
    @DisplayName("logout should return successful AuthResult when user is authenticated")
    void logoutWhenUserIsAuthenticated() {
        when(userRepository.findByUsername("testUser")).thenReturn(Optional.of(testPrincipal));
        when(authProcessor.authenticate(eq(testPrincipal), any(Credentials.class))).thenReturn(
                AuthResult.success("Authentication successful"));
        AuthResult resultAuth = authService.authenticate(testCredentials);
        assertTrue(resultAuth.isSuccess());

        AuthResult result = authService.logout();

        assertTrue(result.isSuccess());
        assertTrue(result.hasMessages());
        assertEquals("Logout successful", result.getMessages().get(0));
        assertTrue(authService.getCurrentUsername().isEmpty());

        AuthResult resultVerify = authService.verifyAuth();
        assertFalse(resultVerify.isSuccess());
        assertTrue(resultVerify.hasMessages());
        assertEquals("User is not authenticated", resultVerify.getMessages().get(0));
    }

    @Test
    @DisplayName("logout should return successful AuthResult with warning when no active session exists")
    void logoutWhenNoActiveSession() {
        AuthResult result = authService.logout();

        assertTrue(result.isSuccess());
        assertTrue(result.hasMessages());
        assertEquals("No active session - logout operation had no effect", result.getMessages().get(0));
        assertTrue(authService.getCurrentUsername().isEmpty());

        AuthResult resultVerify = authService.verifyAuth();
        assertFalse(resultVerify.isSuccess());
        assertTrue(resultVerify.hasMessages());
        assertEquals("User is not authenticated", resultVerify.getMessages().get(0));
    }

    @Test
    @DisplayName("logout should return failed AuthResult when service not initialized")
    void logoutWhenServiceNotInitialized() throws Exception {
        authService = createFreshServiceInstance();

        AuthResult result = authService.logout();

        assertFalse(result.isSuccess());
        assertTrue(result.hasMessages());
        assertEquals("SimpleAuthenticationService not initialized. Call initialize() before using",
                result.getMessages().get(0));
        assertTrue(authService.getCurrentUsername().isEmpty());
    }
}
