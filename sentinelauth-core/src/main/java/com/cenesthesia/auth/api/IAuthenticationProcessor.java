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
     * @see IAuthenticationProcessor#authenticateWithContext(AuthPrincipal, Credentials, Object)
     *
     * @param principal информация о пользователе
     * @param credentials реквизиты аутентификации
     * @return true, если аутентификация успешна, иначе false
     */
    boolean authenticate(AuthPrincipal principal, Credentials credentials);

    /**
     * Выполняет аутентификацию пользователя с учетом дополнительного контекста. Заделка для
     * кастомных сервисов. По умолчанию функционал аналогичен {@link IAuthenticationProcessor#authenticate(AuthPrincipal, Credentials)}
     * @see IAuthenticationProcessor#authenticate(AuthPrincipal, Credentials)
     *
     * @param principal информация о пользователе
     * @param credentials реквизиты аутентификации
     * @param context контекст
     * @return true, если аутентификация успешна, иначе false
     */
    default boolean authenticateWithContext(AuthPrincipal principal, Credentials credentials, Object context) {
        return authenticate(principal, credentials);
    }
}
