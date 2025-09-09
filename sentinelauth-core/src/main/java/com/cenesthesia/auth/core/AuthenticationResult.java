package com.cenesthesia.auth.core;

import com.cenesthesia.auth.common.AuthPrincipal;
import com.cenesthesia.auth.common.Credentials;

/**
 * Результат попытки аутентификации пользователя в системе
 *
 * @author Cenesthesia
 * @version 1.0
 */
public class AuthenticationResult {
    /**Успешность аутентификации (true если успешно иначе false)*/
    private final boolean success;
    /**Аутентифицированный пользователь*/
    private final AuthPrincipal user;
    /**Сообщение с ошибками во время аутентификации (если имеются)*/
    private final String errorMessage;

    /**
     * Конструктор для инициализации результатов аутентификации
     *
     * @param success успешность аутентификации
     * @param user аутентифицированный пользователь
     * @param errorMessage сообщение с ошибками (если имеются)
     */
    AuthenticationResult(boolean success, AuthPrincipal user, String errorMessage) {
        this.success = success;
        this.user = user;
        this.errorMessage = errorMessage;
    }

    /**
     * Возвращает значение поля {@link AuthenticationResult#success}
     *
     * @return успешность аутентификации
     */
    public boolean isSuccess() {
        return success;
    }

    /**
     * Возвращает значение поля {@link AuthenticationResult#user}
     *
     * @return аутентифицированный пользователь
     */
    AuthPrincipal getUser() {
        return user;
    }

    /**
     * Возвращает значение поля {@link AuthenticationResult#errorMessage}
     *
     * @return сообщение с ошибками аутентификации (если имеются)
     */
    public String getErrorMessage() {
        return errorMessage;
    }
}
