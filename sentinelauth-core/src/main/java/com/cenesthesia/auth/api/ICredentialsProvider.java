package com.cenesthesia.auth.api;

import com.cenesthesia.auth.common.Credentials;

/**
 * Источник реквизитов пользователя
 *
 * @author Cenesthesia
 * @version 1.0
 */
public interface ICredentialsProvider {
    /**
     * Предоставляет форму для ввода реквизитов и возвращает их
     *
     * @return реквизиты пользователя
     */
    Credentials provideCredentials();
}
