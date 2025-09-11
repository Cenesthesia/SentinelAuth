package com.cenesthesia.auth.common;

import java.util.Arrays;
import java.util.Objects;

/**
 * Реквизиты пользователя проходящего аутентификацию
 *
 * @author Cenesthesia
 * @version 1.0
 */
public class Credentials {
    /**Идентификатор пользователя*/
    private String userIdentifier;
    /**Идентификационный ключ пользователя*/
    private char[] password;

    /**
     * Конструктор - инициализирует реквизиты пользователя
     * {@link Credentials#userIdentifier}, {@link Credentials#password}
     *
     * @param userIdentifier идентификатор пользователя
     * @param password идентификационный ключ пользователя
     */
    public Credentials(String userIdentifier, char[] password) {
        this.userIdentifier = userIdentifier;
        this.password = password;
    }

    /**
     * Возвращает идентификатор пользователя
     *
     * @return значение поля {@link Credentials#userIdentifier}
     */
    public String getUserIdentifier() {
        return userIdentifier;
    }

    /**
     * Устанавливает новый идентификатор пользователя
     *
     * @param userIdentifier новое значение для поля {@link Credentials#userIdentifier}
     */
    public void setUserIdentifier(String userIdentifier) {
        this.userIdentifier = userIdentifier;
    }

    /**
     * Возвращает идентификационный ключ пользователя
     *
     * @return значение поля {@link Credentials#password}
     */
    public char[] getPassword() {
        return password;
    }

    /**
     * Устанавливает новый идентификационный ключ пользователя
     *
     * @param password новое значение для поля {@link Credentials#password}
     */
    public void setPassword(char[] password) {
        this.password = password;
    }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof Credentials)) return false;
        Credentials that = (Credentials) o;
        return Objects.equals(userIdentifier, that.userIdentifier) && Objects.deepEquals(password, that.password);
    }

    @Override
    public int hashCode() {
        return Objects.hash(userIdentifier, Arrays.hashCode(password));
    }

    @Override
    public String toString() {
        return String.format("Credentials{userIdentifier='%s', password=%s'}", userIdentifier, password == null ? "null" : "*****");
    }
}
