package com.cenesthesia.auth.utils;


import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

/**
 * Утилита для безопасной работы с паролями.
 * Методы являются thread-safe и защищены от timing attacks.
 *
 * @author Cenesthesia
 * @version 1.0
 */
public class PasswordSecurityUtils {
    //TODO: Можно вынести параметры в файл конфигурации библиотеки (!Может стать уязвимостью)
    /**Количество итераций алгоритма PBKDF2*/
    private static final int PBKDF2_ITERATIONS = 100000;
    /**Длина ключа PBKDF2*/
    private static final int PBKDF2_KEY_LENGTH = 256;
    /**Длина соли PBKDF2*/
    private static final int SALT_LENGTH = 16;
    /**Минимальная длина пароля*/
    private static final int MIN_PASSWORD_LENGTH = 8;
    /**Длина пароля по умолчанию*/
    private static final int STANDARD_PASSWORD_LENGTH = 16;
    /**Криптографически стойкий генератор случайных чисел*/
    private static final SecureRandom secureRandom = new SecureRandom();

    /**
     * Приватный конструктор для предотвращения инстанцирования
     *
     * @throws AssertionError при попытке инстанцирования
     */
    private PasswordSecurityUtils() {
        throw new AssertionError("Cannot instantiate utility class");
    }

    /**
     * Преобразование пароля в виде массива char в безопасный byte[]. Используемая кодировка UTF-8.
     * <div style="border: 1px solid #d4edda; padding: 10px; margin: 10px 0;">
     *   <em><b> ВАЖНО!</b></em>: Принятый пароль в виде char[] будет затёрт для предотвращения утечек.
     * </div>
     * @param password пароль в символьном представлении
     * @return пароль в байтовом представлении
     * @throws IllegalArgumentException если {@code password} null или empty
     */
    public static byte[] passwordToBytes(char[] password) {
        if (password == null || password.length == 0) {
            throw new IllegalArgumentException("Password cannot be null or empty");
        }

        try {
            String passwordStr = new String(password);
            return passwordStr.getBytes(StandardCharsets.UTF_8);
        } finally {
            Arrays.fill(password, '\u0000');
        }
    }

    /**
     * Восстановление пароля из массива byte. Является Deprecated и не рекомендуется к использованию.
     * Используемая кодировка UTF-8.
     * <div style="border: 1px solid #d4edda; padding: 10px; margin: 10px 0;">
     *   <em><b> ВАЖНО!</b></em>: Метод пытается восстановить пароль на основе кодировки UTF-8. Метод не
     *   является безопасным: принимаемый байтовый пароль не затирается, восстановление может быть не точным,
     *   а также нарушает принцип хранения паролей.
     * </div>
     *
     * @param bytes пароль в байтовом представлении
     * @return пароль в символьном представлении
     * @throws IllegalArgumentException если {@code bytes} null или empty
     */
    @Deprecated
    public static char[] bytesToPassword(byte[] bytes) {
        if (bytes == null || bytes.length == 0) {
            throw new IllegalArgumentException("Byte array cannot be null or empty");
        }

        String passwordStr = new String(bytes, StandardCharsets.UTF_8);
        return passwordStr.toCharArray();
    }

    /**
     * Хэширование пароля с использованием соли и алгоритмов PBKDF2 и SHA256.
     * <div style="border: 1px solid #d4edda; padding: 10px; margin: 10px 0;">
     *   <em><b> ВАЖНО!</b></em>: Принятый пароль в виде char[] будет затёрт для предотвращения утечек.
     * </div>
     *
     * @param password хэшируемый пароль
     * @param salt соль
     * @return хэш пароля/безопасный ключ
     * @throws IllegalArgumentException если {@code password} или {@code salt} empty, или null
     * @throws RuntimeException если не удалось инстанцировать алгоритм/ы PBKDF2 и/или SHA256,
     *                          или сгенерировать безопасный ключ (см. Exception message)
     */
    public static byte[] hashPassword(char[] password, byte[] salt) {
        if (password == null || password.length == 0) {
            throw new IllegalArgumentException("Password cannot be null or empty");
        }
        if (salt == null || salt.length == 0) {
            throw new IllegalArgumentException("Salt cannot be null or empty");
        }

        try {
            PBEKeySpec spec = new PBEKeySpec(password, salt, PBKDF2_ITERATIONS, PBKDF2_KEY_LENGTH);
            SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            return skf.generateSecret(spec).getEncoded();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("PBKDF2 algorithm not available", e);
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException("PBKDF2 cannot generate key secret", e);
        } finally {
            Arrays.fill(password, '\u0000');
        }
    }

    /**
     * Генерация криптографически безопасной соли.
     *
     * @return соль
     */
    public static byte[] generateSalt() {
        byte[] salt = new byte[SALT_LENGTH];
        secureRandom.nextBytes(salt);
        return salt;
    }

    /**
     * Сравнение паролей/хэшей с защитой от timing attacks.
     *
     * @param bytes1 первый пароль для сравнения
     * @param bytes2 второй пароль для сравнения
     * @return true если пароли совпадают, иначе false
     */
    public static boolean constantTimeEquals(byte[] bytes1, byte[] bytes2) {
        if (bytes1 == null || bytes2 == null) {
            return false;
        }
        if (bytes1.length != bytes2.length) { //TODO: Можно убрать, уязвима к timing attacks
            return false;
        }

        int result = 0;
        for (int i = 0; i < bytes1.length; i++) {
            result |= bytes1[i] ^ bytes2[i];
        }
        return result == 0;
    }

    /**
     * Сравнение пароля с хэшем пароля (вместе с солью).
     *
     * @param inputPassword введенный пароль
     * @param storeHash хэш существующего пароля
     * @param salt соль хэша
     * @return true если пароль и хэш совпадают, иначе false
     * @throws IllegalArgumentException если {@code inputPassword} или {@code storeHash} или {@code salt} null или empty (см. Exception massage)
     */
    public static boolean verifyPassword(char[] inputPassword, byte[] storeHash, byte[] salt) {
        if (inputPassword == null || inputPassword.length == 0) {
            throw new IllegalArgumentException("Input password cannot be null or empty");
        }
        if (storeHash == null || storeHash.length == 0) {
            throw new IllegalArgumentException("Stored hash cannot be null or empty");
        }
        if (salt == null || salt.length == 0) {
            throw new IllegalArgumentException("Salt cannot be null or empty");
        }

        try {
            byte[] testHash = hashPassword(Arrays.copyOf(inputPassword, inputPassword.length), salt);
            return constantTimeEquals(testHash, storeHash);
        } finally {
            Arrays.fill(inputPassword, '\u0000');
        }
    }

    /**
     * Безопасная очистка (затирание) byte[]
     * @param bytes очищаемый массив байт
     */
    public static void clearBytes(byte[] bytes) {
        if (bytes != null) {
            Arrays.fill(bytes, (byte) 0);
        }
    }

    /**
     * Безопасная очистка (затирание) char[]
     *
     * @param chars очищаемый массива символов
     */
    public static void clearChars(char[] chars) {
        if (chars != null) {
            Arrays.fill(chars, '\u0000');
        }
    }

    /**
     * Проверка сложности пароля.
     * Условия:
     * <ul>
     *     <li>Длина не меньше чем {@value MIN_PASSWORD_LENGTH}</li>
     *     <li>Хотя бы один символ в нижнем регистре</li>
     *     <li>Хотя бы один символ в верхнем регистре</li>
     *     <li>Хотя бы одна цифра</li>
     *     <li>Хотя бы один спецсимвол из "!@#$%^&*()_+-=[]{}|;:,.<>?"</li>
     * </ul>
     *
     * @param password проверяемый пароль
     * @return true если пароль удовлетворяет условиям, иначе false
     */
    public static boolean isPasswordStrong(char[] password) {
        if (password == null || password.length < MIN_PASSWORD_LENGTH) {
            return false;
        }

        boolean hasUpper = false;
        boolean hasLower = false;
        boolean hasDigit = false;
        boolean hasSpecial = false;

        for (char c : password) {
            if (Character.isUpperCase(c)) {
                hasUpper = true;
            } else if (Character.isLowerCase(c)) {
                hasLower = true;
            } else if (Character.isDigit(c)) {
                hasDigit = true;
            } else if (!Character.isLetterOrDigit(c)) {
                hasSpecial = true;
            }
        }

        Arrays.fill(password, '\u0000');

        return hasUpper && hasLower && hasDigit && hasSpecial;
    }

    /**
     * Генерирует случайный безопасный пароль длинной {@code length}.
     *
     * @param length длина пароля (не меньше {@value MIN_PASSWORD_LENGTH})
     * @return безопасный пароль
     * @throws IllegalArgumentException если переданная длина {@code length} меньше {@value MIN_PASSWORD_LENGTH}
     */
    public static char[] generateSecurePassword(int length) {
        if (length < MIN_PASSWORD_LENGTH) {
            throw new IllegalArgumentException("Password length must be at least 8 characters");
        }

        String uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        String lowercase = "abcdefghijklmnopqrstuvwxyz";
        String digits = "0123456789";
        String specials = "!@#$%^&*()_+-=[]{}|;:,.<>?";

        String allChars = uppercase + lowercase + digits + specials;
        char[] password = new char[length];

        password[0] = uppercase.charAt(secureRandom.nextInt(uppercase.length()));
        password[1] = lowercase.charAt(secureRandom.nextInt(lowercase.length()));
        password[2] = digits.charAt(secureRandom.nextInt(digits.length()));
        password[3] = specials.charAt(secureRandom.nextInt(specials.length()));

        for (int i = 4; i < length; i++) {
            password[i] = allChars.charAt(secureRandom.nextInt(allChars.length()));
        }

        for (int i = 0; i < password.length; i++) {
            int randomIndex = secureRandom.nextInt(password.length);
            char temp = password[i];
            password[i] = password[randomIndex];
            password[randomIndex] = temp;
        }

        return password;
    }

    /**
     * Перегрузка {@link PasswordSecurityUtils#generateSecurePassword(int)}.
     * Генерирует случайный безопасный пароль длинною {@value STANDARD_PASSWORD_LENGTH} символов.
     *
     * @see PasswordSecurityUtils#generateSecurePassword(int)
     *
     * @return безопасный пароль длинною {@value STANDARD_PASSWORD_LENGTH} символов
     */
    public static char[] generateSecurePassword() {
        return generateSecurePassword(STANDARD_PASSWORD_LENGTH);
    }
}
