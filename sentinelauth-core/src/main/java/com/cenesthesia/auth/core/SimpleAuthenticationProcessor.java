package com.cenesthesia.auth.core;

import com.cenesthesia.auth.api.IAuthenticationProcessor;
import com.cenesthesia.auth.common.AuthPrincipal;
import com.cenesthesia.auth.common.Credentials;
import com.cenesthesia.auth.utils.PasswordSecurityUtils;

import java.util.Arrays;

/**
 * Базовый сервис аутентификации, проверяющий совпадение паролей на основе алгоритма PBKDF2
 *
 * @author Cenesthesia
 * @version 1.0
 */
public class SimpleAuthenticationProcessor implements IAuthenticationProcessor {
    @Override
    public boolean authenticate(AuthPrincipal principal, Credentials credentials) {
        boolean isSuccess = principal != null && credentials != null && principal.getUsername() != null && credentials.getUserIdentifier() != null
                && principal.getUsername().length > 0 && credentials.getUserIdentifier().length > 0
                && principal.getPasswordHash() != null && credentials.getPassword() != null && principal.getSalt() != null
                && principal.getPasswordHash().length > 0 && credentials.getPassword().length > 0 && principal.getSalt().length > 0
                && Arrays.equals(credentials.getUserIdentifier(), principal.getUsername())
                && PasswordSecurityUtils.verifyPassword(credentials.getPassword(), principal.getPasswordHash(), principal.getSalt());
        if (credentials != null)
            PasswordSecurityUtils.clearChars(credentials.getUserIdentifier());
        return isSuccess;
    }
}
