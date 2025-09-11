package com.cenesthesia.auth.api;

import com.cenesthesia.auth.common.AuthPrincipal;
import com.cenesthesia.auth.common.Credentials;

/**
 * Интерфейс для реализаций непосредственно самого этапа аутентификации
 *
 * @author Cenesthesia
 * @version 1.0
 */
public interface IAuthenticationProcessor {
    /**
     * Выполняет аутентификацию пользователя
     *
     * @param principal информация о пользователе
     * @param credentials реквизиты аутентификации
     * @return результат аутентификации с сообщениями об ошибках (если имеются)
     */
    boolean authenticate(AuthPrincipal principal, Credentials credentials);
}
