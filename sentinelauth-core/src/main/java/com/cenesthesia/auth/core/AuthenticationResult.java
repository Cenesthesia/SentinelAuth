package com.cenesthesia.auth.core;

import com.cenesthesia.auth.common.AuthPrincipal;

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
     * Возвращает если авторизация успешна true, иначе false
     *
     * @return значение поля {@link AuthenticationResult#success}
     */
    public boolean isSuccess() {
        return success;
    }

    /**
     * Возвращает аутентифицированного пользователя
     *
     * @return значение поля {@link AuthenticationResult#user}
     */
    AuthPrincipal getUser() {
        return user;
    }

    /**
     * Возвращает сообщение с ошибками аутентификации (если имеются)
     *
     * @return значение поля {@link AuthenticationResult#errorMessage}
     */
    public String getErrorMessage() {
        return errorMessage;
    }
}
