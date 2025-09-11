package com.cenesthesia.auth.core;

import com.cenesthesia.auth.api.IAuthenticationProcessor;
import com.cenesthesia.auth.common.AuthPrincipal;
import com.cenesthesia.auth.common.Credentials;
import com.cenesthesia.auth.utils.PasswordSecurityUtils;

//TODO: Проверка на пустые username?

/**
 * Базовый сервис аутентификации, проверяющий совпадение паролей на основе алгоритма PBKDF2
 *
 * @author Cenesthesia
 * @version 1.0
 */
public class SimpleAuthenticationProcessor implements IAuthenticationProcessor {
    @Override
    public boolean authenticate(AuthPrincipal principal, Credentials credentials) {
        return principal != null && credentials != null && principal.getUsername() != null && credentials.getUserIdentifier() != null
                && principal.getPasswordHash() != null && credentials.getPassword() != null && principal.getSalt() != null
                && principal.getPasswordHash().length > 0 && credentials.getPassword().length > 0 && principal.getSalt().length > 0
                && credentials.getUserIdentifier().equals(principal.getUsername())
                && PasswordSecurityUtils.verifyPassword(credentials.getPassword(), principal.getPasswordHash(), principal.getSalt());
    }
}
