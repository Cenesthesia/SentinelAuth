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
    private byte[] password;

    /**
     * Конструктор - инициализирует реквизиты пользователя
     * {@link Credentials#userIdentifier}, {@link Credentials#password}
     *
     * @param userIdentifier идентификатор пользователя
     * @param password идентификационный ключ пользователя
     */
    public Credentials(String userIdentifier, byte[] password) {
        this.userIdentifier = userIdentifier;
        this.password = password;
    }

    /**
     * Возвращает значение поля {@link Credentials#userIdentifier}
     *
     * @return идентификатор пользователя
     */
    public String getUserIdentifier() {
        return userIdentifier;
    }

    /**
     * Устанавливает значение для поля {@link Credentials#userIdentifier}
     *
     * @param userIdentifier новый идентификатор пользователя
     */
    public void setUserIdentifier(String userIdentifier) {
        this.userIdentifier = userIdentifier;
    }

    /**
     * Возвращает значение поля {@link Credentials#password}
     *
     * @return идентификационный ключ пользователя
     */
    public byte[] getPassword() {
        return password;
    }

    /**
     * Устанавливает значение для поля {@link Credentials#password}
     *
     * @param password новый идентификационный ключ пользователя
     */
    public void setPassword(byte[] password) {
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
