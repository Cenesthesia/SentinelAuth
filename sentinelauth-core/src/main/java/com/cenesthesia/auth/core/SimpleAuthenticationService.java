package com.cenesthesia.auth.core;

import com.cenesthesia.auth.api.AuthenticationService;
import com.cenesthesia.auth.common.AuthPrincipal;
import com.cenesthesia.auth.common.Credentials;

import java.util.Collection;
import java.util.Optional;

public class SimpleAuthenticationService extends AuthenticationService {
    private SimpleAuthenticationService() {

    }

    public static AuthenticationService getInstance() {
        if (INSTANCE == null) {
            synchronized (SimpleAuthenticationService.class) {
                if (INSTANCE == null) {
                    INSTANCE = new SimpleAuthenticationService();
                }
            }
        }
        return INSTANCE;
    }

    @Override
    public synchronized boolean authenticate(Credentials credentials) {
        checkInitialization();
        resetState();
        try {
            Optional<AuthPrincipal> user = repository.findByUsername(credentials.getUserIdentifier());
            if (user.isEmpty())
                throw new AuthException(String.format("The user with the identifier %s was not found in the repository",
                        credentials.getUserIdentifier()));
            isAuthenticated.set(authenticate.authenticate(principal.get(), credentials));
            if (!isAuthenticated.get())
                resetState();
            else
                principal.set(user.get());
            return isAuthenticated.get();
        } catch (Exception e) {
            resetState();
            throw new AuthException(String.format("Authentication error: %s", e.getMessage()), e);
        }
    }

    @Override
    public boolean requireAuthenticate() throws AuthException {
        checkInitialization();
        checkCredentialsProvider();
        resetState();
        try {
            Credentials credentials = null;
            Optional<AuthPrincipal> user = Optional.empty();
            do {
                credentials = credentialsProvider.get().provideCredentials();
                user = repository.findByUsername(credentials.getUserIdentifier());
                isAuthenticated.set(authenticate.authenticate(principal.get(), credentials));
            } while(!isAuthenticated.get() && !requireBreak.get());
            if (requireBreak.get()) {
                requireBreak.set(false);
                isAuthenticated.set(false);
            }
            if (!isAuthenticated.get())
                resetState();
            else
                principal.set(user.get());
            return isAuthenticated.get();
        } catch (Exception e) {
            resetState();
            throw new AuthException(String.format("Authentication error: %s", e.getMessage()), e);
        }
    }

    @Override
    public synchronized boolean logout() {
        try {
            checkInitialization();
            checkAuthenticate();
            resetState();
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    @Override
    public synchronized boolean logout(String id) {
        try {
            checkInitialization();
            checkAuthenticate();
            if (principal.get().getId().equals(id) || principal.get().getUsername().equals(id)) {
                resetState();
                return true;
            } else {
                return false;
            }
        } catch (Exception e) {
            return false;
        }
    }

    @Override
    public synchronized boolean verifyAuth() {
        checkInitialization();
        return isAuthenticated.get();
    }

    @Override
    public synchronized boolean hasRole(String role) {
        checkInitialization();
        checkAuthenticate();
        return authorization.hasRole(principal.get(), role);
    }

    @Override
    public boolean requireRole(String role) {
        checkInitialization();
        if (!isAuthenticated.get())
            requireAuthenticate();
        if (!isAuthenticated.get()) {
            return false;
        }
        return authorization.hasRole(principal.get(), role);
    }

    @Override
    public synchronized boolean hasAllRoles(Collection<String> roles) {
        checkInitialization();
        checkAuthenticate();
        return authorization.hasAllRoles(principal.get(), roles);
    }

    @Override
    public boolean requireAllRoles(Collection<String> roles) {
        checkInitialization();
        if (!isAuthenticated.get())
            requireAuthenticate();
        if (!isAuthenticated.get()) {
            return false;
        }
        return authorization.hasAllRoles(principal.get(), roles);
    }

    @Override
    public synchronized boolean hasAnyRole(Collection<String> roles) {
        checkInitialization();
        checkAuthenticate();
        return authorization.hasAnyRole(principal.get(), roles);
    }

    @Override
    public boolean requireAnyRole(Collection<String> roles) {
        checkInitialization();
        if (!isAuthenticated.get())
            requireAuthenticate();
        if (!isAuthenticated.get()) {
            return false;
        }
        return authorization.hasAnyRole(principal.get(), roles);
    }

    @Override
    public synchronized boolean hasAnyRoles(Collection<String> roles, int count) {
        checkInitialization();
        checkAuthenticate();
        return authorization.hasAnyRoles(principal.get(), roles, count);
    }

    @Override
    public boolean requireAnyRoles(Collection<String> roles, int count) {
        checkInitialization();
        if (!isAuthenticated.get())
            requireAuthenticate();
        if (!isAuthenticated.get()) {
            return false;
        }
        return authorization.hasAnyRoles(principal.get(), roles, count);
    }

    @Override
    public synchronized boolean hasPermission(String permission) {
        checkInitialization();
        checkAuthenticate();
        return authorization.hasPermission(principal.get(), permission);
    }

    @Override
    public boolean requirePermission(String permission) {
        checkInitialization();
        if (!isAuthenticated.get())
            requireAuthenticate();
        if (!isAuthenticated.get()) {
            return false;
        }
        return authorization.hasPermission(principal.get(), permission);
    }

    @Override
    public synchronized boolean hasAllPermissions(Collection<String> permissions) {
        checkInitialization();
        checkAuthenticate();
        return authorization.hasAllPermissions(principal.get(), permissions);
    }

    @Override
    public boolean requireAllPermissions(Collection<String> permissions) {
        checkInitialization();
        if (!isAuthenticated.get())
            requireAuthenticate();
        if (!isAuthenticated.get()) {
            return false;
        }
        return authorization.hasAllPermissions(principal.get(), permissions);
    }

    @Override
    public synchronized boolean hasAnyPermission(Collection<String> permissions) {
        checkInitialization();
        checkAuthenticate();
        return authorization.hasAnyPermission(principal.get(), permissions);
    }

    @Override
    public boolean requireAnyPermission(Collection<String> permissions) {
        checkInitialization();
        if (!isAuthenticated.get())
            requireAuthenticate();
        if (!isAuthenticated.get()) {
            return false;
        }
        return authorization.hasAnyPermission(principal.get(), permissions);
    }

    @Override
    public synchronized boolean hasAnyPermissions(Collection<String> permissions, int count) {
        checkInitialization();
        checkAuthenticate();
        return authorization.hasAnyPermissions(principal.get(), permissions, count);
    }

    @Override
    public boolean requireAnyPermissions(Collection<String> permissions, int count) {
        checkInitialization();
        if (!isAuthenticated.get())
            requireAuthenticate();
        if (!isAuthenticated.get()) {
            return false;
        }
        return authorization.hasAnyPermissions(principal.get(), permissions, count);
    }
}
