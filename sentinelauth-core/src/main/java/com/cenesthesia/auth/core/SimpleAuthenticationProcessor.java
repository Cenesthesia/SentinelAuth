package com.cenesthesia.auth.core;

import com.cenesthesia.auth.api.IAuthenticationProcessor;
import com.cenesthesia.auth.common.AuthPrincipal;
import com.cenesthesia.auth.common.AuthResult;
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
    public AuthResult authenticate(AuthPrincipal principal, Credentials credentials) {
        try {
            if (principal == null) {
                return AuthResult.failure("Authenticate principal cannot be null");
            }
            if (credentials == null) {
                return AuthResult.failure("Credentials cannot be null");
            }

            if (principal.getUsername() == null || credentials.getUserIdentifier() == null) {
                return AuthResult.failure("Principal or credentials user identifier is null");
            }

            if (principal.getUsername().length == 0 || credentials.getUserIdentifier().length == 0) {
                return AuthResult.failure("Principal or credentials user identifier is empty");
            }

            if (!Arrays.equals(principal.getUsername(), credentials.getUserIdentifier())) {
                return AuthResult.failure("Principal user identifier does not match credentials identifier");
            }

            if (principal.getPasswordHash() == null || credentials.getPassword() == null || principal.getSalt() == null) {
                return AuthResult.failure("Password hash, password or salt is null");
            }

            if (principal.getPasswordHash().length == 0 || credentials.getPassword().length == 0
                || principal.getSalt().length == 0) {
                return AuthResult.failure("Password hash, password or salt is empty");
            }

            boolean passwordValid = PasswordSecurityUtils.verifyPassword(
                    credentials.getPassword(),
                    principal.getPasswordHash(),
                    principal.getSalt()
            );

            if (!passwordValid) {
                return AuthResult.failure("Password verification failed");
            }

            PasswordSecurityUtils.clearChars(credentials.getUserIdentifier());
            return AuthResult.success("Authentication successful");
        } catch (Exception e) {
            return AuthResult.failure("Unexpected error during authentication", e);
        } finally {
            if (credentials != null) {
                PasswordSecurityUtils.clearChars(credentials.getUserIdentifier());
            }
        }
    }
}
