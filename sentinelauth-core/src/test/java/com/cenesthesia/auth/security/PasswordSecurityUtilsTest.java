package com.cenesthesia.auth.security;

import com.cenesthesia.auth.utils.PasswordSecurityUtils;
import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.util.Arrays;


@Tag("unit")
public class PasswordSecurityUtilsTest {
    private byte[] testSalt;

    @BeforeEach
    void setUp() {
        testSalt = new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    }

    @Test
    @DisplayName("clearBytes and clearChars should clear arrays and does not throw exception")
    void testClearMethods() {
        byte[] bytes = new byte[]{1, 2, 3, 4, 5, 6, 7, 8};
        char[] chars = new char[]{'a', 'b', 'c', 'd', 'e', 'e', 'f'};

        PasswordSecurityUtils.clearBytes(bytes);
        PasswordSecurityUtils.clearChars(chars);

        for (byte b : bytes) {
            assertEquals(0, b);
        }
        for (char c : chars) {
            assertEquals('\u0000', c);
        }

        assertDoesNotThrow(() -> PasswordSecurityUtils.clearBytes(bytes));
        assertDoesNotThrow(() -> PasswordSecurityUtils.clearChars(chars));
    }

    @Test
    @DisplayName("generateSalt should return salt of correct length")
    void testGenerateSalt() {
        byte[] salt = PasswordSecurityUtils.generateSalt();
        assertNotNull(salt);
        assertEquals(16, salt.length); //TODO: Убрать константу

        boolean allZeros = true;
        for (byte b : salt) {
            if (b != 0) {
                allZeros = false;
                break;
            }
        }
        assertFalse(allZeros);
    }

    @Test
    @DisplayName("isPasswordStrong should check password strength correctly")
    void testIsPasswordStrong() {
        assertFalse(PasswordSecurityUtils.isPasswordStrong(null));
        assertFalse(PasswordSecurityUtils.isPasswordStrong("short".toCharArray()));
        assertFalse(PasswordSecurityUtils.isPasswordStrong("lowercaseonly".toCharArray()));
        assertFalse(PasswordSecurityUtils.isPasswordStrong("UPPERCASEONLY".toCharArray()));
        assertFalse(PasswordSecurityUtils.isPasswordStrong("12345678".toCharArray()));
        assertFalse(PasswordSecurityUtils.isPasswordStrong("%^&*!@#$%^&*".toCharArray()));
        assertFalse(PasswordSecurityUtils.isPasswordStrong("%^&*!@#$%^&*".toCharArray()));

        assertTrue(PasswordSecurityUtils.isPasswordStrong("GfhjK643m&Q1".toCharArray()));
        assertTrue(PasswordSecurityUtils.isPasswordStrong("teRTvly246*!-".toCharArray()));
    }

    @Test
    @DisplayName("isPasswordStrong should clear password input")
    void testIsPasswordStrongClearsInput() {
        char[] password = ")re_LXTm5-M72.zN".toCharArray();
        PasswordSecurityUtils.isPasswordStrong(password);

        for (char c : password) {
            assertEquals('\u0000', c);
        }
    }

    @Test
    @DisplayName("generateSecurePassword should generate password of correct length")
    void testGenerateSecurePasswordLength() {
        int length = 16;
        char[] password = PasswordSecurityUtils.generateSecurePassword(length);
        assertNotNull(password);
        assertEquals(length, password.length);

        PasswordSecurityUtils.clearChars(password);
    }

    @Test
    @DisplayName("generateSecurePassword should throw exception for short length of password")
    void testGenerateSecurePasswordValidation() {
        int shortLength = 3;
        assertThrows(IllegalArgumentException.class, () -> PasswordSecurityUtils.generateSecurePassword(shortLength));
    }

    @Test
    @DisplayName("generateSecurePassword should generate password contain all required character types")
    void testGenerateSecurePasswordContent() {
        int length = 16;
        char[] password = PasswordSecurityUtils.generateSecurePassword(length);

        boolean hasLower = false;
        boolean hasUpper = false;
        boolean hasDigit = false;
        boolean hasSpecial = false;

        for (char c : password) {
            if (Character.isLowerCase(c)) hasLower = true;
            else if (Character.isUpperCase(c)) hasUpper = true;
            else if (Character.isDigit(c)) hasDigit = true;
            else if (!Character.isLetterOrDigit(c)) hasSpecial = true;
        }

        assertTrue(hasLower, "Should contain lowercase");
        assertTrue(hasUpper, "Should contain uppercase");
        assertTrue(hasDigit, "Should contain digit");
        assertTrue(hasSpecial, "Should contain special character");

        PasswordSecurityUtils.clearChars(password);
    }

    @Test
    @DisplayName("passwordToBytes should convert char[] to byte[] and clear original")
    void testPasswordToBytesClearsOriginal() {
        char[] password = "?pr8NqBJZFl@8e-y".toCharArray();
        byte[] result = PasswordSecurityUtils.passwordToBytes(password);

        assertNotNull(result);
        assertTrue(result.length > 0);

        for (char c : password) {
            assertEquals('\u0000', c);
        }
    }

    @Test
    @DisplayName("passwordToBytes should throw exception for null or empty password")
    void testPasswordToBytesValidation() {
        assertThrows(IllegalArgumentException.class, () -> PasswordSecurityUtils.passwordToBytes(null));
        assertThrows(IllegalArgumentException.class, () -> PasswordSecurityUtils.passwordToBytes(new char[0]));
    }

    @Test
    @DisplayName("bytesToPassword should convert byte[] to char[] password")
    @Deprecated
    void testBytesToPassword() {
        byte[] bytes = "}2o|3!HxfBH,ysn?".getBytes();
        char[] password = PasswordSecurityUtils.bytesToPassword(bytes);

        assertNotNull(password);
        assertTrue(password.length > 0);
    }

    @Test
    @DisplayName("bytesToPassword should throw exception for null or empty byte[]")
    @Deprecated
    void testBytesToPasswordValidation() {
        assertThrows(IllegalArgumentException.class, () -> PasswordSecurityUtils.bytesToPassword(null));
        assertThrows(IllegalArgumentException.class, () -> PasswordSecurityUtils.bytesToPassword(new byte[0]));
    }

    @Test
    @DisplayName("hashPassword should return same hash for same input and salt")
    void testHashPasswordConsistency() {
        char[] password = "u4=R1i+AUl#,L@8S".toCharArray();
        char[] reference = Arrays.copyOf(password, password.length);

        byte[] passwordHash = PasswordSecurityUtils.hashPassword(password, testSalt);
        byte[] referenceHash = PasswordSecurityUtils.hashPassword(reference, testSalt);

        assertArrayEquals(passwordHash, referenceHash);
        assertNotNull(passwordHash);
        assertTrue(passwordHash.length > 0);
    }

    @Test
    @DisplayName("hashPassword should clear password[]")
    void testHashPasswordClearsInput() {
        char[] password = "K9.8S}vgV*hrh;Gx".toCharArray();
        PasswordSecurityUtils.hashPassword(password, testSalt);

        for (char c : password) {
            assertEquals('\u0000', c);
        }
    }

    @Test
    @DisplayName("hashPassword should throw exception for null or empty inputs")
    void testHashPasswordValidation() {
        int saltLength = 16;
        char[] validPassword = "<.XA:mxn#QznqaT6".toCharArray();
        byte[] validSalt = new byte[saltLength];

        assertThrows(IllegalArgumentException.class, () -> PasswordSecurityUtils.hashPassword(null, validSalt));
        assertThrows(IllegalArgumentException.class, () -> PasswordSecurityUtils.hashPassword(new char[0], validSalt));
        assertThrows(IllegalArgumentException.class, () -> PasswordSecurityUtils.hashPassword(validPassword, null));
        assertThrows(IllegalArgumentException.class, () -> PasswordSecurityUtils.hashPassword(validPassword, new byte[0]));
        assertDoesNotThrow(() -> PasswordSecurityUtils.hashPassword(validPassword, validSalt));
    }

    @Test
    @DisplayName("constantTimeEquals should correctly compare byte arrays")
    void testConstantTimeEquals() {
        byte[] array1 = new byte[]{1, 2, 3};
        byte[] array2 = new byte[]{1, 2, 3};
        byte[] array3 = new byte[]{1, 2, 4};
        byte[] array4 = new byte[]{1, 2};

        assertTrue(PasswordSecurityUtils.constantTimeEquals(array1, array2));
        assertFalse(PasswordSecurityUtils.constantTimeEquals(array1, array3));
        assertFalse(PasswordSecurityUtils.constantTimeEquals(array1, array4));
        assertFalse(PasswordSecurityUtils.constantTimeEquals(null, array1));
        assertFalse(PasswordSecurityUtils.constantTimeEquals(array1, null));
        assertFalse(PasswordSecurityUtils.constantTimeEquals(null, null));
    }

    @Test
    @DisplayName("verifyPassword should return true if password is correct")
    void testVerifyPasswordCorrect() {
        char[] originalPassword = "Cm8&Ckqz2h6,KOH0".toCharArray();
        byte[] storedHash = PasswordSecurityUtils.hashPassword(Arrays.copyOf(originalPassword, originalPassword.length),
                testSalt);

        char[] inputPassword = "Cm8&Ckqz2h6,KOH0".toCharArray();
        boolean result = PasswordSecurityUtils.verifyPassword(inputPassword, storedHash, testSalt);

        assertTrue(result);
    }

    @Test
    @DisplayName("verifyPassword should return false if password is incorrect")
    void testVerifyPasswordIncorrect() {
        char[] originalPassword = "iqE@,G1a<6;?P)T%".toCharArray();
        byte[] storedHash = PasswordSecurityUtils.hashPassword(Arrays.copyOf(originalPassword, originalPassword.length),
                testSalt);

        char[] wrongPassword = "wrongPassword".toCharArray();
        boolean result = PasswordSecurityUtils.verifyPassword(wrongPassword, storedHash, testSalt);

        assertFalse(result);
    }

    @Test
    @DisplayName("verifyPassword should clear input password")
    void testVerifyPasswordClearsInput() {
        char[] originalPassword = "Ajo%0MHr?ccL;S!q".toCharArray();
        byte[] storedHash = PasswordSecurityUtils.hashPassword(Arrays.copyOf(originalPassword, originalPassword.length),
                testSalt);

        char[] inputPassword = Arrays.copyOf(originalPassword, originalPassword.length);
        PasswordSecurityUtils.verifyPassword(inputPassword, storedHash, testSalt);

        for (char c : inputPassword) {
            assertEquals('\u0000', c);
        }
    }

    @Test
    @DisplayName("verifyPassword should throw exception for null or empty inputs")
    void testVerifyPasswordValidation() {
        byte[] validHash = new byte[256];

        assertThrows(IllegalArgumentException.class, () -> PasswordSecurityUtils.verifyPassword(null, validHash, testSalt));
        assertThrows(IllegalArgumentException.class, () -> PasswordSecurityUtils.verifyPassword(new char[0], validHash, testSalt));
        assertThrows(IllegalArgumentException.class, () -> PasswordSecurityUtils.verifyPassword("password".toCharArray(), null, testSalt));
        assertThrows(IllegalArgumentException.class, () -> PasswordSecurityUtils.verifyPassword("password".toCharArray(), new byte[0], testSalt));
        assertThrows(IllegalArgumentException.class, () -> PasswordSecurityUtils.verifyPassword("password".toCharArray(), validHash, null));
        assertThrows(IllegalArgumentException.class, () -> PasswordSecurityUtils.verifyPassword("password".toCharArray(), validHash, new byte[0]));
        assertDoesNotThrow(() -> PasswordSecurityUtils.verifyPassword("password".toCharArray(), validHash, testSalt));
    }
}
