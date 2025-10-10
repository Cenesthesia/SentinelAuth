package com.cenesthesia.auth.services;

import com.cenesthesia.auth.api.IAuthUserRepository;
import com.cenesthesia.auth.api.IAuthenticationProcessor;
import com.cenesthesia.auth.api.IAuthorizationProcessor;
import com.cenesthesia.auth.api.ICredentialsProvider;
import com.cenesthesia.auth.common.AuthPrincipal;
import com.cenesthesia.auth.common.AuthResult;
import com.cenesthesia.auth.common.Credentials;
import com.cenesthesia.auth.core.SimpleAuthenticationService;
import org.junit.jupiter.api.*;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;
import org.mockito.MockedStatic;
import static org.mockito.Mockito.*;

import java.lang.reflect.Field;
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
}
