package com.cenesthesia.auth.core;

/**
 * Класс для ошибок во время работы сервиса аутентификации
 *
 * @author Cenesthesia
 * @version 1.0
 */
public class AuthException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    public AuthException(String message) {
        super(message);
    }

    public AuthException(String message, Throwable cause) {
        super(message, cause);
    }
}
