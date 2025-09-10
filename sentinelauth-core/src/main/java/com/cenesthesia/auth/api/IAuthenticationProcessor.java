package com.cenesthesia.auth.api;

import com.cenesthesia.auth.common.AuthPrincipal;
import com.cenesthesia.auth.common.Credentials;
import com.cenesthesia.auth.core.AuthenticationResult;

/**
 * Интерфейс для реализаций непосредственно самого этапа аутентификации
 *
 * @author Cenesthesia
 * @version 1.0
 */
public interface IAuthenticationProcessor {
    /**
     * Выполнить аутентификацию пользователя
     *
     * @param principal информация о пользователе
     * @param credentials реквизиты аутентификации
     * @return результат аутентификации с сообщениями об ошибках (если имеются)
     */
    AuthenticationResult authenticate(AuthPrincipal principal, Credentials credentials);
}
