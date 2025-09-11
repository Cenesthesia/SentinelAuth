package com.cenesthesia.auth.services;

import com.cenesthesia.auth.api.IAuthenticationProcessor;
import com.cenesthesia.auth.common.AuthPrincipal;
import com.cenesthesia.auth.common.Credentials;
import com.cenesthesia.auth.core.SimpleAuthenticationProcessor;
import com.cenesthesia.auth.utils.PasswordSecurityUtils;
import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Set;

@Tag("unit")
public class SimpleAuthenticationProcessorTest {
    private IAuthenticationProcessor auth;
    private AuthPrincipal principal;

    @BeforeEach
    void setUp() {
        auth = new SimpleAuthenticationProcessor();
        principal = new AuthPrincipal("1", "testUser");
    }

    //===================================== authenticate tests =========================================================

    @Test
    @DisplayName("authenticate should return true when credentials password and username is correct for principal")
    void authenticateWhenPasswordAndUsernameIsCorrect() {
        char[] password = "testPassword".toCharArray();
        byte[] salt = new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
        principal.setPasswordHash(PasswordSecurityUtils.hashPassword(Arrays.copyOf(password, password.length), salt));
        principal.setSalt(salt);
        Credentials credentials = new Credentials("testUser", password);;
        boolean result = auth.authenticate(principal, credentials);
        assertTrue(result);
    }

    @Test
    @DisplayName("authenticate should return false when credentials password is incorrect for principal")
    void authenticateWhenPasswordIsIncorrect() {
        char[] password = "testPassword".toCharArray();
        byte[] salt = new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
        principal.setPasswordHash(PasswordSecurityUtils.hashPassword(password, salt));
        principal.setSalt(salt);
        Credentials credentials = new Credentials("testUser", "otherPassword".toCharArray());;
        boolean result = auth.authenticate(principal, credentials);
        assertFalse(result);
    }

    @Test
    @DisplayName("authenticate should return false when credentials username is incorrect for principal")
    void authenticateWhenUsernameIsIncorrect() {
        char[] password = "testPassword".toCharArray();
        byte[] salt = new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
        principal.setPasswordHash(PasswordSecurityUtils.hashPassword(Arrays.copyOf(password, password.length), salt));
        principal.setSalt(salt);
        Credentials credentials = new Credentials("otherUser", password);;
        boolean result = auth.authenticate(principal, credentials);
        assertFalse(result);
    }

    @Test
    @DisplayName("authenticate should return false when principal password is null")
    void authenticateWhenPrincipalPasswordIsNull() {
        char[] password = "testPassword".toCharArray();
        byte[] salt = new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
        principal.setPasswordHash(null);
        principal.setSalt(salt);
        Credentials credentials = new Credentials("testUser", password);
        boolean result = auth.authenticate(principal, credentials);
        assertFalse(result);
    }

    @Test
    @DisplayName("authenticate should return false when principal password is empty")
    void authenticateWhenPrincipalPasswordIsEmpty() {
        char[] password = "testPassword".toCharArray();
        byte[] salt = new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
        principal.setPasswordHash(new byte[0]);
        principal.setSalt(salt);
        Credentials credentials = new Credentials("testUser", password);
        boolean result = auth.authenticate(principal, credentials);
        assertFalse(result);
    }

    @Test
    @DisplayName("authenticate should return false when principal salt is null")
    void authenticateWhenPrincipalSaltIsNull() {
        char[] password = "testPassword".toCharArray();
        byte[] salt = new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
        principal.setPasswordHash(PasswordSecurityUtils.hashPassword(Arrays.copyOf(password, password.length), salt));
        principal.setSalt(null);
        Credentials credentials = new Credentials("testUser", password);
        boolean result = auth.authenticate(principal, credentials);
        assertFalse(result);
    }

    @Test
    @DisplayName("authenticate should return false when principal salt is empty")
    void authenticateWhenPrincipalSaltIsEmpty() {
        char[] password = "testPassword".toCharArray();
        byte[] salt = new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
        principal.setPasswordHash(PasswordSecurityUtils.hashPassword(Arrays.copyOf(password, password.length), salt));
        principal.setSalt(new byte[0]);
        Credentials credentials = new Credentials("testUser", password);
        boolean result = auth.authenticate(principal, credentials);
        assertFalse(result);
    }

    @Test
    @DisplayName("authenticate should return false when principal username is null")
    void authenticateWhenPrincipalUsernameIsNull() {
        char[] password = "testPassword".toCharArray();
        byte[] salt = new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
        principal.setUsername(null);
        principal.setPasswordHash(PasswordSecurityUtils.hashPassword(Arrays.copyOf(password, password.length), salt));
        principal.setSalt(salt);
        Credentials credentials = new Credentials("testUser", password);
        boolean result = auth.authenticate(principal, credentials);
        assertFalse(result);
    }

    @Test
    @DisplayName("authenticate should return false when credentials password is null")
    void authenticateWhenCredentialsPasswordIsNull() {
        char[] password = "testPassword".toCharArray();
        byte[] salt = new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
        principal.setPasswordHash(PasswordSecurityUtils.hashPassword(Arrays.copyOf(password, password.length), salt));
        principal.setSalt(salt);
        Credentials credentials = new Credentials("testUser", null);
        boolean result = auth.authenticate(principal, credentials);
        assertFalse(result);
    }

    @Test
    @DisplayName("authenticate should return false when credentials password is empty")
    void authenticateWhenCredentialsPasswordIsEmpty() {
        char[] password = "testPassword".toCharArray();
        byte[] salt = new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
        principal.setPasswordHash(PasswordSecurityUtils.hashPassword(Arrays.copyOf(password, password.length), salt));
        principal.setSalt(salt);
        Credentials credentials = new Credentials("testUser", new char[0]);
        boolean result = auth.authenticate(principal, credentials);
        assertFalse(result);
    }

    @Test
    @DisplayName("authenticate should return false when credentials userIndf is null")
    void authenticateWhenCredentialsUserIndfIsNull() {
        char[] password = "testPassword".toCharArray();
        byte[] salt = new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
        principal.setPasswordHash(PasswordSecurityUtils.hashPassword(Arrays.copyOf(password, password.length), salt));
        principal.setSalt(salt);
        Credentials credentials = new Credentials(null, password);
        boolean result = auth.authenticate(principal, credentials);
        assertFalse(result);
    }

    @Test
    @DisplayName("authenticate should return false when principal is null")
    void authenticateWhenPrincipalIsNull() {
        char[] password = "testPassword".toCharArray();
        Credentials credentials = new Credentials("testUser", password);
        boolean result = auth.authenticate(null, credentials);
        assertFalse(result);
    }

    @Test
    @DisplayName("authenticate should return false when credentials is null")
    void authenticateWhenCredentialsIsNull() {
        char[] password = "testPassword".toCharArray();
        byte[] salt = new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
        principal.setPasswordHash(PasswordSecurityUtils.hashPassword(Arrays.copyOf(password, password.length), salt));
        principal.setSalt(salt);
        boolean result = auth.authenticate(principal, null);
        assertFalse(result);
    }

    //================================ authenticateWithContext tests ===================================================

    @Test
    @DisplayName("authenticateWithContext should work like authenticate and return true when credentials password and " +
            "username is correct for principal")
    void authenticateWithContextWhenPasswordAndUsernameIsCorrect() {
        char[] password = "testPassword".toCharArray();
        byte[] salt = new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
        principal.setPasswordHash(PasswordSecurityUtils.hashPassword(Arrays.copyOf(password, password.length), salt));
        principal.setSalt(salt);
        Credentials credentials = new Credentials("testUser", password);;
        boolean result = auth.authenticateWithContext(principal, credentials, new Object());
        assertTrue(result);
    }

    @Test
    @DisplayName("authenticateWithContext should work like authenticate and return false when credentials password is " +
            "incorrect for principal")
    void authenticateWithContextWhenPasswordIsIncorrect() {
        char[] password = "testPassword".toCharArray();
        byte[] salt = new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
        principal.setPasswordHash(PasswordSecurityUtils.hashPassword(password, salt));
        principal.setSalt(salt);
        Credentials credentials = new Credentials("testUser", "otherPassword".toCharArray());;
        boolean result = auth.authenticateWithContext(principal, credentials, new Object());
        assertFalse(result);
    }

    @Test
    @DisplayName("authenticateWithContext should work like authenticate and return false when credentials username is " +
            "incorrect for principal")
    void authenticateWithContextWhenUsernameIsIncorrect() {
        char[] password = "testPassword".toCharArray();
        byte[] salt = new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
        principal.setPasswordHash(PasswordSecurityUtils.hashPassword(Arrays.copyOf(password, password.length), salt));
        principal.setSalt(salt);
        Credentials credentials = new Credentials("otherUser", password);;
        boolean result = auth.authenticateWithContext(principal, credentials, new Object());
        assertFalse(result);
    }

    @Test
    @DisplayName("authenticateWithContext should work like authenticate and return false when principal password is null")
    void authenticateWithContextWhenPrincipalPasswordIsNull() {
        char[] password = "testPassword".toCharArray();
        byte[] salt = new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
        principal.setPasswordHash(null);
        principal.setSalt(salt);
        Credentials credentials = new Credentials("testUser", password);
        boolean result = auth.authenticateWithContext(principal, credentials, new Object());
        assertFalse(result);
    }

    @Test
    @DisplayName("authenticateWithContext should work like authenticate and return false when principal password is empty")
    void authenticateWithContextWhenPrincipalPasswordIsEmpty() {
        char[] password = "testPassword".toCharArray();
        byte[] salt = new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
        principal.setPasswordHash(new byte[0]);
        principal.setSalt(salt);
        Credentials credentials = new Credentials("testUser", password);
        boolean result = auth.authenticateWithContext(principal, credentials, new Object());
        assertFalse(result);
    }

    @Test
    @DisplayName("authenticateWithContext should work like authenticate and return false when principal salt is null")
    void authenticateWithContextWhenPrincipalSaltIsNull() {
        char[] password = "testPassword".toCharArray();
        byte[] salt = new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
        principal.setPasswordHash(PasswordSecurityUtils.hashPassword(Arrays.copyOf(password, password.length), salt));
        principal.setSalt(null);
        Credentials credentials = new Credentials("testUser", password);
        boolean result = auth.authenticateWithContext(principal, credentials, new Object());
        assertFalse(result);
    }

    @Test
    @DisplayName("authenticateWithContext should work like authenticate and return false when principal salt is empty")
    void authenticateWithContextWhenPrincipalSaltIsEmpty() {
        char[] password = "testPassword".toCharArray();
        byte[] salt = new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
        principal.setPasswordHash(PasswordSecurityUtils.hashPassword(Arrays.copyOf(password, password.length), salt));
        principal.setSalt(new byte[0]);
        Credentials credentials = new Credentials("testUser", password);
        boolean result = auth.authenticateWithContext(principal, credentials, new Object());
        assertFalse(result);
    }

    @Test
    @DisplayName("authenticateWithContext should work like authenticate and return false when principal username is null")
    void authenticateWithContextWhenPrincipalUsernameIsNull() {
        char[] password = "testPassword".toCharArray();
        byte[] salt = new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
        principal.setUsername(null);
        principal.setPasswordHash(PasswordSecurityUtils.hashPassword(Arrays.copyOf(password, password.length), salt));
        principal.setSalt(salt);
        Credentials credentials = new Credentials("testUser", password);
        boolean result = auth.authenticateWithContext(principal, credentials, new Object());
        assertFalse(result);
    }

    @Test
    @DisplayName("authenticateWithContext should work like authenticate return false when credentials password is null")
    void authenticateWithContextWhenCredentialsPasswordIsNull() {
        char[] password = "testPassword".toCharArray();
        byte[] salt = new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
        principal.setPasswordHash(PasswordSecurityUtils.hashPassword(Arrays.copyOf(password, password.length), salt));
        principal.setSalt(salt);
        Credentials credentials = new Credentials("testUser", null);
        boolean result = auth.authenticateWithContext(principal, credentials, new Object());
        assertFalse(result);
    }

    @Test
    @DisplayName("authenticateWithContext should work like authenticate and return false when credentials password is empty")
    void authenticateWithContextWhenCredentialsPasswordIsEmpty() {
        char[] password = "testPassword".toCharArray();
        byte[] salt = new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
        principal.setPasswordHash(PasswordSecurityUtils.hashPassword(Arrays.copyOf(password, password.length), salt));
        principal.setSalt(salt);
        Credentials credentials = new Credentials("testUser", new char[0]);
        boolean result = auth.authenticateWithContext(principal, credentials, new Object());
        assertFalse(result);
    }

    @Test
    @DisplayName("authenticateWithContext should work like authenticate and return false when credentials userIndf is null")
    void authenticateWithContextWhenCredentialsUserIndfIsNull() {
        char[] password = "testPassword".toCharArray();
        byte[] salt = new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
        principal.setPasswordHash(PasswordSecurityUtils.hashPassword(Arrays.copyOf(password, password.length), salt));
        principal.setSalt(salt);
        Credentials credentials = new Credentials(null, password);
        boolean result = auth.authenticateWithContext(principal, credentials, new Object());
        assertFalse(result);
    }

    @Test
    @DisplayName("authenticateWithContext should work like authenticate and return false when principal is null")
    void authenticateWithContextWhenPrincipalIsNull() {
        char[] password = "testPassword".toCharArray();
        Credentials credentials = new Credentials("testUser", password);
        boolean result = auth.authenticateWithContext(null, credentials, new Object());
        assertFalse(result);
    }

    @Test
    @DisplayName("authenticateWithContext should work like authenticate and return false when credentials is null")
    void authenticateWithContextWhenCredentialsIsNull() {
        char[] password = "testPassword".toCharArray();
        byte[] salt = new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
        principal.setPasswordHash(PasswordSecurityUtils.hashPassword(Arrays.copyOf(password, password.length), salt));
        principal.setSalt(salt);
        boolean result = auth.authenticateWithContext(principal, null, new Object());
        assertFalse(result);
    }

    @Test
    @DisplayName("authenticateWithContext should work like authenticate no matter the context")
    void authenticateWithContextDoesNotDependOnContext() {
        String username = "testUser";
        char[] password = "testPassword".toCharArray();
        byte[] salt = new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
        principal.setPasswordHash(PasswordSecurityUtils.hashPassword(Arrays.copyOf(password, password.length), salt));
        principal.setSalt(salt);
        boolean resultObjectContextWithCorrectPassword = auth.authenticateWithContext(principal,
                new Credentials(username, Arrays.copyOf(password, password.length)), new Object());
        boolean resultObjectContextWithWrongPassword = auth.authenticateWithContext(principal,
                new Credentials(username, "otherPassword".toCharArray()), new Object());
        boolean resultNullContextWithCorrectPassword = auth.authenticateWithContext(principal,
                new Credentials(username, Arrays.copyOf(password, password.length)), null);
        boolean resultNullContextWithWrongPassword = auth.authenticateWithContext(principal,
                new Credentials(username, "otherPassword".toCharArray()), null);
        boolean resultOtherContextWithCorrectPassword = auth.authenticateWithContext(principal,
                new Credentials(username, Arrays.copyOf(password, password.length)), "context");
        boolean resultOtherContextWithWrongPassword = auth.authenticateWithContext(principal,
                new Credentials(username, "otherPassword".toCharArray()), "context");
        assertTrue(resultObjectContextWithCorrectPassword);
        assertFalse(resultObjectContextWithWrongPassword);
        assertTrue(resultNullContextWithCorrectPassword);
        assertFalse(resultNullContextWithWrongPassword);
        assertTrue(resultOtherContextWithCorrectPassword);
        assertFalse(resultOtherContextWithWrongPassword);
    }
}
