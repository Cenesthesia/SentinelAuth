package com.cenesthesia.auth.common;

import com.cenesthesia.auth.utils.PasswordSecurityUtils;

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
    private char[] userIdentifier;
    /**Идентификационный ключ пользователя*/
    private char[] password;

    /**
     * Конструктор - инициализирует реквизиты пользователя
     * {@link Credentials#userIdentifier}, {@link Credentials#password}
     *
     * @param userIdentifier идентификатор пользователя
     * @param password идентификационный ключ пользователя
     */
    public Credentials(char[] userIdentifier, char[] password) {
        this.userIdentifier = userIdentifier;
        this.password = password;
    }

    /**
     * Возвращает идентификатор пользователя
     *
     * @return значение поля {@link Credentials#userIdentifier}
     */
    public char[] getUserIdentifier() {
        return userIdentifier;
    }

    /**
     * Устанавливает новый идентификатор пользователя.
     * В качестве меры безопасности предыдущее значение будет затерто.
     *
     * @param userIdentifier новое значение для поля {@link Credentials#userIdentifier}
     */
    public void setUserIdentifier(char[] userIdentifier) {
        PasswordSecurityUtils.clearChars(this.userIdentifier);
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
     * Устанавливает новый идентификационный ключ пользователя.
     * В качестве меры безопасности предыдущее значение будет затерто.
     *
     * @param password новое значение для поля {@link Credentials#password}
     */
    public void setPassword(char[] password) {
        PasswordSecurityUtils.clearChars(this.password);
        this.password = password;
    }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof Credentials)) return false;
        Credentials that = (Credentials) o;
        return Objects.deepEquals(userIdentifier, that.userIdentifier) && Objects.deepEquals(password, that.password);
    }

    @Override
    public int hashCode() {
        return Objects.hash(Arrays.hashCode(userIdentifier), Arrays.hashCode(password));
    }

    @Override
    public String toString() {
        return String.format("Credentials{userIdentifier='%s', password=%s'}", Arrays.toString(userIdentifier), password == null ? "null" : "*****");
    }
}
