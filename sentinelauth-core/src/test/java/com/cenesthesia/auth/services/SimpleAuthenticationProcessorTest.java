package com.cenesthesia.auth.services;

import com.cenesthesia.auth.api.IAuthenticationProcessor;
import com.cenesthesia.auth.common.AuthPrincipal;
import com.cenesthesia.auth.common.AuthResult;
import com.cenesthesia.auth.common.Credentials;
import com.cenesthesia.auth.core.SimpleAuthenticationProcessor;
import com.cenesthesia.auth.utils.PasswordSecurityUtils;
import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.util.Arrays;

@Tag("unit")
public class SimpleAuthenticationProcessorTest {
    private IAuthenticationProcessor auth;
    private AuthPrincipal principal;

    @BeforeEach
    void setUp() {
        auth = new SimpleAuthenticationProcessor();
        principal = new AuthPrincipal("1".toCharArray(), "testUser".toCharArray());
    }

    //===================================== authenticate tests =========================================================

    @Test
    @DisplayName("authenticate should return successful AuthResult when credentials password and username is correct for principal")
    void authenticateWhenPasswordAndUsernameIsCorrect() {
        char[] password = "testPassword".toCharArray();
        byte[] salt = new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
        principal.setPasswordHash(PasswordSecurityUtils.hashPassword(Arrays.copyOf(password, password.length), salt));
        principal.setSalt(salt);
        Credentials credentials = new Credentials("testUser".toCharArray(), password);
        AuthResult result = auth.authenticate(principal, credentials);
        assertTrue(result.isSuccess());
        assertTrue(result.hasMessages());
        assertFalse(result.hasExceptions());
        assertEquals("Authentication successful", result.getMessages().get(0));
    }

    @Test
    @DisplayName("authenticate should return failed AuthResult when credentials password is incorrect for principal")
    void authenticateWhenPasswordIsIncorrect() {
        char[] password = "testPassword".toCharArray();
        byte[] salt = new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
        principal.setPasswordHash(PasswordSecurityUtils.hashPassword(password, salt));
        principal.setSalt(salt);
        Credentials credentials = new Credentials("testUser".toCharArray(), "otherPassword".toCharArray());
        AuthResult result = auth.authenticate(principal, credentials);
        assertFalse(result.isSuccess());
        assertTrue(result.hasMessages());
        assertFalse(result.hasExceptions());
        assertEquals("Password verification failed", result.getMessages().get(0));
    }

    @Test
    @DisplayName("authenticate should return failed AuthResult when credentials username is incorrect for principal")
    void authenticateWhenUsernameIsIncorrect() {
        char[] password = "testPassword".toCharArray();
        byte[] salt = new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
        principal.setPasswordHash(PasswordSecurityUtils.hashPassword(Arrays.copyOf(password, password.length), salt));
        principal.setSalt(salt);
        Credentials credentials = new Credentials("otherUser".toCharArray(), password);
        AuthResult result = auth.authenticate(principal, credentials);
        assertFalse(result.isSuccess());
        assertTrue(result.hasMessages());
        assertFalse(result.hasExceptions());
        assertEquals("Principal user identifier does not match credentials identifier", result.getMessages().get(0));
    }

    @Test
    @DisplayName("authenticate should return failed AuthResult when principal password is null")
    void authenticateWhenPrincipalPasswordIsNull() {
        char[] password = "testPassword".toCharArray();
        byte[] salt = new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
        principal.setPasswordHash(null);
        principal.setSalt(salt);
        Credentials credentials = new Credentials("testUser".toCharArray(), password);
        AuthResult result = auth.authenticate(principal, credentials);
        assertFalse(result.isSuccess());
        assertTrue(result.hasMessages());
        assertFalse(result.hasExceptions());
        assertEquals("Password hash, password or salt is null", result.getMessages().get(0));
    }

    @Test
    @DisplayName("authenticate should return failed AuthResult when principal password is empty")
    void authenticateWhenPrincipalPasswordIsEmpty() {
        char[] password = "testPassword".toCharArray();
        byte[] salt = new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
        principal.setPasswordHash(new byte[0]);
        principal.setSalt(salt);
        Credentials credentials = new Credentials("testUser".toCharArray(), password);
        AuthResult result = auth.authenticate(principal, credentials);
        assertFalse(result.isSuccess());
        assertTrue(result.hasMessages());
        assertFalse(result.hasExceptions());
        assertEquals("Password hash, password or salt is empty", result.getMessages().get(0));
    }

    @Test
    @DisplayName("authenticate should return failed AuthResult when principal salt is null")
    void authenticateWhenPrincipalSaltIsNull() {
        char[] password = "testPassword".toCharArray();
        byte[] salt = new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
        principal.setPasswordHash(PasswordSecurityUtils.hashPassword(Arrays.copyOf(password, password.length), salt));
        principal.setSalt(null);
        Credentials credentials = new Credentials("testUser".toCharArray(), password);
        AuthResult result = auth.authenticate(principal, credentials);
        assertFalse(result.isSuccess());
        assertTrue(result.hasMessages());
        assertFalse(result.hasExceptions());
        assertEquals("Password hash, password or salt is null", result.getMessages().get(0));
    }

    @Test
    @DisplayName("authenticate should return failed AuthResult when principal salt is empty")
    void authenticateWhenPrincipalSaltIsEmpty() {
        char[] password = "testPassword".toCharArray();
        byte[] salt = new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
        principal.setPasswordHash(PasswordSecurityUtils.hashPassword(Arrays.copyOf(password, password.length), salt));
        principal.setSalt(new byte[0]);
        Credentials credentials = new Credentials("testUser".toCharArray(), password);
        AuthResult result = auth.authenticate(principal, credentials);
        assertFalse(result.isSuccess());
        assertTrue(result.hasMessages());
        assertFalse(result.hasExceptions());
        assertEquals("Password hash, password or salt is empty", result.getMessages().get(0));
    }

    @Test
    @DisplayName("authenticate should return failed AuthResult when principal username is null")
    void authenticateWhenPrincipalUsernameIsNull() {
        char[] password = "testPassword".toCharArray();
        byte[] salt = new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
        principal.setUsername(null);
        principal.setPasswordHash(PasswordSecurityUtils.hashPassword(Arrays.copyOf(password, password.length), salt));
        principal.setSalt(salt);
        Credentials credentials = new Credentials("testUser".toCharArray(), password);
        AuthResult result = auth.authenticate(principal, credentials);
        assertFalse(result.isSuccess());
        assertTrue(result.hasMessages());
        assertFalse(result.hasExceptions());
        assertEquals("Principal or credentials user identifier is null", result.getMessages().get(0));
    }

    @Test
    @DisplayName("authenticate should return failed AuthResult when principal username is empty")
    void authenticateWhenPrincipalUsernameIsEmpty() {
        char[] password = "testPassword".toCharArray();
        byte[] salt = new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
        principal.setUsername(new char[0]);
        principal.setPasswordHash(PasswordSecurityUtils.hashPassword(Arrays.copyOf(password, password.length), salt));
        principal.setSalt(salt);
        Credentials credentials = new Credentials("testUser".toCharArray(), password);
        AuthResult result = auth.authenticate(principal, credentials);
        assertFalse(result.isSuccess());
        assertTrue(result.hasMessages());
        assertFalse(result.hasExceptions());
        assertEquals("Principal or credentials user identifier is empty", result.getMessages().get(0));
    }

    @Test
    @DisplayName("authenticate should return failed AuthResult when credentials password is null")
    void authenticateWhenCredentialsPasswordIsNull() {
        char[] password = "testPassword".toCharArray();
        byte[] salt = new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
        principal.setPasswordHash(PasswordSecurityUtils.hashPassword(Arrays.copyOf(password, password.length), salt));
        principal.setSalt(salt);
        Credentials credentials = new Credentials("testUser".toCharArray(), null);
        AuthResult result = auth.authenticate(principal, credentials);
        assertFalse(result.isSuccess());
        assertTrue(result.hasMessages());
        assertFalse(result.hasExceptions());
        assertEquals("Password hash, password or salt is null", result.getMessages().get(0));
    }

    @Test
    @DisplayName("authenticate should return failed AuthResult when credentials password is empty")
    void authenticateWhenCredentialsPasswordIsEmpty() {
        char[] password = "testPassword".toCharArray();
        byte[] salt = new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
        principal.setPasswordHash(PasswordSecurityUtils.hashPassword(Arrays.copyOf(password, password.length), salt));
        principal.setSalt(salt);
        Credentials credentials = new Credentials("testUser".toCharArray(), new char[0]);
        AuthResult result = auth.authenticate(principal, credentials);
        assertFalse(result.isSuccess());
        assertTrue(result.hasMessages());
        assertFalse(result.hasExceptions());
        assertEquals("Password hash, password or salt is empty", result.getMessages().get(0));
    }

    @Test
    @DisplayName("authenticate should return failed AuthResult when credentials userIndf is null")
    void authenticateWhenCredentialsUserIndfIsNull() {
        char[] password = "testPassword".toCharArray();
        byte[] salt = new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
        principal.setPasswordHash(PasswordSecurityUtils.hashPassword(Arrays.copyOf(password, password.length), salt));
        principal.setSalt(salt);
        Credentials credentials = new Credentials(null, password);
        AuthResult result = auth.authenticate(principal, credentials);
        assertFalse(result.isSuccess());
        assertTrue(result.hasMessages());
        assertFalse(result.hasExceptions());
        assertEquals("Principal or credentials user identifier is null", result.getMessages().get(0));
    }

    @Test
    @DisplayName("authenticate should return failed AuthResult when credentials userIndf is empty")
    void authenticateWhenCredentialsUserIndfIsEmpty() {
        char[] password = "testPassword".toCharArray();
        byte[] salt = new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
        principal.setPasswordHash(PasswordSecurityUtils.hashPassword(Arrays.copyOf(password, password.length), salt));
        principal.setSalt(salt);
        Credentials credentials = new Credentials(new char[0], password);
        AuthResult result = auth.authenticate(principal, credentials);
        assertFalse(result.isSuccess());
        assertTrue(result.hasMessages());
        assertFalse(result.hasExceptions());
        assertEquals("Principal or credentials user identifier is empty", result.getMessages().get(0));
    }

    @Test
    @DisplayName("authenticate should return failed AuthResult when principal is null")
    void authenticateWhenPrincipalIsNull() {
        char[] password = "testPassword".toCharArray();
        Credentials credentials = new Credentials("testUser".toCharArray(), password);
        AuthResult result = auth.authenticate(null, credentials);
        assertFalse(result.isSuccess());
        assertTrue(result.hasMessages());
        assertFalse(result.hasExceptions());
        assertEquals("Authenticate principal cannot be null", result.getMessages().get(0));
    }

    @Test
    @DisplayName("authenticate should return failed AuthResult when credentials is null")
    void authenticateWhenCredentialsIsNull() {
        char[] password = "testPassword".toCharArray();
        byte[] salt = new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
        principal.setPasswordHash(PasswordSecurityUtils.hashPassword(Arrays.copyOf(password, password.length), salt));
        principal.setSalt(salt);
        AuthResult result = auth.authenticate(principal, null);
        assertFalse(result.isSuccess());
        assertTrue(result.hasMessages());
        assertFalse(result.hasExceptions());
        assertEquals("Credentials cannot be null", result.getMessages().get(0));
    }

    //================================ authenticateWithContext tests ===================================================

    @Test
    @DisplayName("authenticateWithContext should work like authenticate and return successful AuthResult when " +
            "credentials password and username is correct for principal")
    void authenticateWithContextWhenPasswordAndUsernameIsCorrect() {
        char[] password = "testPassword".toCharArray();
        byte[] salt = new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
        principal.setPasswordHash(PasswordSecurityUtils.hashPassword(Arrays.copyOf(password, password.length), salt));
        principal.setSalt(salt);
        Credentials credentials = new Credentials("testUser".toCharArray(), password);
        AuthResult result = auth.authenticateWithContext(principal, credentials, new Object());
        assertTrue(result.isSuccess());
        assertTrue(result.hasMessages());
        assertFalse(result.hasExceptions());
        assertEquals("Authentication successful", result.getMessages().get(0));
    }

    @Test
    @DisplayName("authenticateWithContext should work like authenticate and return failed AuthResult when " +
            "credentials password is incorrect for principal")
    void authenticateWithContextWhenPasswordIsIncorrect() {
        char[] password = "testPassword".toCharArray();
        byte[] salt = new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
        principal.setPasswordHash(PasswordSecurityUtils.hashPassword(password, salt));
        principal.setSalt(salt);
        Credentials credentials = new Credentials("testUser".toCharArray(), "otherPassword".toCharArray());
        AuthResult result = auth.authenticateWithContext(principal, credentials, new Object());
        assertFalse(result.isSuccess());
        assertTrue(result.hasMessages());
        assertFalse(result.hasExceptions());
        assertEquals("Password verification failed", result.getMessages().get(0));
    }

    @Test
    @DisplayName("authenticateWithContext should work like authenticate and return failed AuthResult when credentials " +
            "username is incorrect for principal")
    void authenticateWithContextWhenUsernameIsIncorrect() {
        char[] password = "testPassword".toCharArray();
        byte[] salt = new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
        principal.setPasswordHash(PasswordSecurityUtils.hashPassword(Arrays.copyOf(password, password.length), salt));
        principal.setSalt(salt);
        Credentials credentials = new Credentials("otherUser".toCharArray(), password);
        AuthResult result = auth.authenticateWithContext(principal, credentials, new Object());
        assertFalse(result.isSuccess());
        assertTrue(result.hasMessages());
        assertFalse(result.hasExceptions());
        assertEquals("Principal user identifier does not match credentials identifier", result.getMessages().get(0));
    }

    @Test
    @DisplayName("authenticateWithContext should work like authenticate and return failed AuthResult when principal " +
            "password is null")
    void authenticateWithContextWhenPrincipalPasswordIsNull() {
        char[] password = "testPassword".toCharArray();
        byte[] salt = new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
        principal.setPasswordHash(null);
        principal.setSalt(salt);
        Credentials credentials = new Credentials("testUser".toCharArray(), password);
        AuthResult result = auth.authenticateWithContext(principal, credentials, new Object());
        assertFalse(result.isSuccess());
        assertTrue(result.hasMessages());
        assertFalse(result.hasExceptions());
        assertEquals("Password hash, password or salt is null", result.getMessages().get(0));
    }

    @Test
    @DisplayName("authenticateWithContext should work like authenticate and return failed AuthResult when principal " +
            "password is empty")
    void authenticateWithContextWhenPrincipalPasswordIsEmpty() {
        char[] password = "testPassword".toCharArray();
        byte[] salt = new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
        principal.setPasswordHash(new byte[0]);
        principal.setSalt(salt);
        Credentials credentials = new Credentials("testUser".toCharArray(), password);
        AuthResult result = auth.authenticateWithContext(principal, credentials, new Object());
        assertFalse(result.isSuccess());
        assertTrue(result.hasMessages());
        assertFalse(result.hasExceptions());
        assertEquals("Password hash, password or salt is empty", result.getMessages().get(0));
    }

    @Test
    @DisplayName("authenticateWithContext should work like authenticate and return failed AuthResult when principal " +
            "salt is null")
    void authenticateWithContextWhenPrincipalSaltIsNull() {
        char[] password = "testPassword".toCharArray();
        byte[] salt = new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
        principal.setPasswordHash(PasswordSecurityUtils.hashPassword(Arrays.copyOf(password, password.length), salt));
        principal.setSalt(null);
        Credentials credentials = new Credentials("testUser".toCharArray(), password);
        AuthResult result = auth.authenticateWithContext(principal, credentials, new Object());
        assertFalse(result.isSuccess());
        assertTrue(result.hasMessages());
        assertFalse(result.hasExceptions());
        assertEquals("Password hash, password or salt is null", result.getMessages().get(0));
    }

    @Test
    @DisplayName("authenticateWithContext should work like authenticate and return failed AuthResult when principal " +
            "salt is empty")
    void authenticateWithContextWhenPrincipalSaltIsEmpty() {
        char[] password = "testPassword".toCharArray();
        byte[] salt = new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
        principal.setPasswordHash(PasswordSecurityUtils.hashPassword(Arrays.copyOf(password, password.length), salt));
        principal.setSalt(new byte[0]);
        Credentials credentials = new Credentials("testUser".toCharArray(), password);
        AuthResult result = auth.authenticateWithContext(principal, credentials, new Object());
        assertFalse(result.isSuccess());
        assertTrue(result.hasMessages());
        assertFalse(result.hasExceptions());
        assertEquals("Password hash, password or salt is empty", result.getMessages().get(0));
    }

    @Test
    @DisplayName("authenticateWithContext should work like authenticate and return failed AuthResult when principal " +
            "username is null")
    void authenticateWithContextWhenPrincipalUsernameIsNull() {
        char[] password = "testPassword".toCharArray();
        byte[] salt = new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
        principal.setUsername(null);
        principal.setPasswordHash(PasswordSecurityUtils.hashPassword(Arrays.copyOf(password, password.length), salt));
        principal.setSalt(salt);
        Credentials credentials = new Credentials("testUser".toCharArray(), password);
        AuthResult result = auth.authenticateWithContext(principal, credentials, new Object());
        assertFalse(result.isSuccess());
        assertTrue(result.hasMessages());
        assertFalse(result.hasExceptions());
        assertEquals("Principal or credentials user identifier is null", result.getMessages().get(0));
    }

    @Test
    @DisplayName("authenticateWithContext should work like authenticate and return failed AuthResult when principal " +
            "username is empty")
    void authenticateWithContextWhenPrincipalUsernameIsEmpty() {
        char[] password = "testPassword".toCharArray();
        byte[] salt = new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
        principal.setUsername(new char[0]);
        principal.setPasswordHash(PasswordSecurityUtils.hashPassword(Arrays.copyOf(password, password.length), salt));
        principal.setSalt(salt);
        Credentials credentials = new Credentials("testUser".toCharArray(), password);
        AuthResult result = auth.authenticateWithContext(principal, credentials, new Object());
        assertFalse(result.isSuccess());
        assertTrue(result.hasMessages());
        assertFalse(result.hasExceptions());
        assertEquals("Principal or credentials user identifier is empty", result.getMessages().get(0));
    }

    @Test
    @DisplayName("authenticateWithContext should work like authenticate return failed AuthResult when credentials " +
            "password is null")
    void authenticateWithContextWhenCredentialsPasswordIsNull() {
        char[] password = "testPassword".toCharArray();
        byte[] salt = new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
        principal.setPasswordHash(PasswordSecurityUtils.hashPassword(Arrays.copyOf(password, password.length), salt));
        principal.setSalt(salt);
        Credentials credentials = new Credentials("testUser".toCharArray(), null);
        AuthResult result = auth.authenticateWithContext(principal, credentials, new Object());
        assertFalse(result.isSuccess());
        assertTrue(result.hasMessages());
        assertFalse(result.hasExceptions());
        assertEquals("Password hash, password or salt is null", result.getMessages().get(0));
    }

    @Test
    @DisplayName("authenticateWithContext should work like authenticate and return failed AuthResult when credentials " +
            "password is empty")
    void authenticateWithContextWhenCredentialsPasswordIsEmpty() {
        char[] password = "testPassword".toCharArray();
        byte[] salt = new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
        principal.setPasswordHash(PasswordSecurityUtils.hashPassword(Arrays.copyOf(password, password.length), salt));
        principal.setSalt(salt);
        Credentials credentials = new Credentials("testUser".toCharArray(), new char[0]);
        AuthResult result = auth.authenticateWithContext(principal, credentials, new Object());
        assertFalse(result.isSuccess());
        assertTrue(result.hasMessages());
        assertFalse(result.hasExceptions());
        assertEquals("Password hash, password or salt is empty", result.getMessages().get(0));
    }

    @Test
    @DisplayName("authenticateWithContext should work like authenticate and return failed AuthResult when credentials " +
            "userIndf is null")
    void authenticateWithContextWhenCredentialsUserIndfIsNull() {
        char[] password = "testPassword".toCharArray();
        byte[] salt = new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
        principal.setPasswordHash(PasswordSecurityUtils.hashPassword(Arrays.copyOf(password, password.length), salt));
        principal.setSalt(salt);
        Credentials credentials = new Credentials(null, password);
        AuthResult result = auth.authenticateWithContext(principal, credentials, new Object());
        assertFalse(result.isSuccess());
        assertTrue(result.hasMessages());
        assertFalse(result.hasExceptions());
        assertEquals("Principal or credentials user identifier is null", result.getMessages().get(0));
    }

    @Test
    @DisplayName("authenticateWithContext should work like authenticate and return failed AuthResult when credentials " +
            "userIndf is empty")
    void authenticateWithContextWhenCredentialsUserIndfIsEmpty() {
        char[] password = "testPassword".toCharArray();
        byte[] salt = new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
        principal.setPasswordHash(PasswordSecurityUtils.hashPassword(Arrays.copyOf(password, password.length), salt));
        principal.setSalt(salt);
        Credentials credentials = new Credentials(new char[0], password);
        AuthResult result = auth.authenticateWithContext(principal, credentials, new Object());
        assertFalse(result.isSuccess());
        assertTrue(result.hasMessages());
        assertFalse(result.hasExceptions());
        assertEquals("Principal or credentials user identifier is empty", result.getMessages().get(0));
    }

    @Test
    @DisplayName("authenticateWithContext should work like authenticate and return failed AuthResult when principal is null")
    void authenticateWithContextWhenPrincipalIsNull() {
        char[] password = "testPassword".toCharArray();
        Credentials credentials = new Credentials("testUser".toCharArray(), password);
        AuthResult result = auth.authenticateWithContext(null, credentials, new Object());
        assertFalse(result.isSuccess());
        assertTrue(result.hasMessages());
        assertFalse(result.hasExceptions());
        assertEquals("Authenticate principal cannot be null", result.getMessages().get(0));
    }

    @Test
    @DisplayName("authenticateWithContext should work like authenticate and return failed AuthResult when credentials is null")
    void authenticateWithContextWhenCredentialsIsNull() {
        char[] password = "testPassword".toCharArray();
        byte[] salt = new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
        principal.setPasswordHash(PasswordSecurityUtils.hashPassword(Arrays.copyOf(password, password.length), salt));
        principal.setSalt(salt);
        AuthResult result = auth.authenticateWithContext(principal, null, new Object());
        assertFalse(result.isSuccess());
        assertTrue(result.hasMessages());
        assertFalse(result.hasExceptions());
        assertEquals("Credentials cannot be null", result.getMessages().get(0));
    }

    @Test
    @DisplayName("authenticateWithContext should work like authenticate no matter the context")
    void authenticateWithContextDoesNotDependOnContext() {
        char[] username = "testUser".toCharArray();
        char[] password = "testPassword".toCharArray();
        byte[] salt = new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
        principal.setPasswordHash(PasswordSecurityUtils.hashPassword(Arrays.copyOf(password, password.length), salt));
        principal.setSalt(salt);
        AuthResult resultObjectContextWithCorrectPassword = auth.authenticateWithContext(principal,
                new Credentials(Arrays.copyOf(username, username.length), Arrays.copyOf(password, password.length)), new Object());
        AuthResult resultObjectContextWithWrongPassword = auth.authenticateWithContext(principal,
                new Credentials(Arrays.copyOf(username, username.length), "otherPassword".toCharArray()), new Object());
        AuthResult resultNullContextWithCorrectPassword = auth.authenticateWithContext(principal,
                new Credentials(Arrays.copyOf(username, username.length), Arrays.copyOf(password, password.length)), null);
        AuthResult resultNullContextWithWrongPassword = auth.authenticateWithContext(principal,
                new Credentials(Arrays.copyOf(username, username.length), "otherPassword".toCharArray()), null);
        AuthResult resultOtherContextWithCorrectPassword = auth.authenticateWithContext(principal,
                new Credentials(Arrays.copyOf(username, username.length), Arrays.copyOf(password, password.length)), "context");
        AuthResult resultOtherContextWithWrongPassword = auth.authenticateWithContext(principal,
                new Credentials(Arrays.copyOf(username, username.length), "otherPassword".toCharArray()), "context");
        assertTrue(resultObjectContextWithCorrectPassword.isSuccess());
        assertFalse(resultObjectContextWithWrongPassword.isSuccess());
        assertTrue(resultNullContextWithCorrectPassword.isSuccess());
        assertFalse(resultNullContextWithWrongPassword.isSuccess());
        assertTrue(resultOtherContextWithCorrectPassword.isSuccess());
        assertFalse(resultOtherContextWithWrongPassword.isSuccess());
    }
}
