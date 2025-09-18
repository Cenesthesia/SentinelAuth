package com.cenesthesia.auth.services;

import com.cenesthesia.auth.api.IAuthorizationProcessor;
import com.cenesthesia.auth.common.AuthPrincipal;
import com.cenesthesia.auth.common.AuthResult;
import com.cenesthesia.auth.core.SimpleAuthorizationProcessor;
import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.util.Set;

@Tag("unit")
public class SimpleAuthorizationProcessorTest {
    private IAuthorizationProcessor authorizationService;
    private AuthPrincipal principal;

    @BeforeEach
    void setUp() {
        authorizationService = new SimpleAuthorizationProcessor();
        principal = new AuthPrincipal("1", "testUser");
    }

    //=============================== hasRole tests ===========================================

    @Test
    @DisplayName("hasRole should return successful AuthResult when user has the role")
    void hasRoleWhenUserHasRole() {
        principal.setRoles(Set.of("admin", "user"));
        String role = "admin";

        AuthResult result = authorizationService.hasRole(principal, role);
        assertTrue(result.isSuccess());
        assertTrue(result.hasMessages());
        assertFalse(result.hasExceptions());
        assertEquals("User has required role: " + role, result.getMessages().get(0));
    }

    @Test
    @DisplayName("hasRole should return failed AuthResult when user doesn't have the role")
    void hasRoleWhenUserDoesNotHaveRole() {
        principal.setRoles(Set.of("user"));
        String role = "admin";

        AuthResult result = authorizationService.hasRole(principal, role);
        assertFalse(result.isSuccess());
        assertTrue(result.hasMessages());
        assertFalse(result.hasExceptions());
        assertEquals("User does not have required role: " + role, result.getMessages().get(0));
    }

    @Test
    @DisplayName("hasRole should return failed AuthResult when user roles is null")
    void hasRoleWhenUserRolesIsNull() {
        principal.setRoles(null);
        String role = "admin";

        AuthResult result = authorizationService.hasRole(principal, role);
        assertFalse(result.isSuccess());
        assertTrue(result.hasMessages());
        assertFalse(result.hasExceptions());
        assertEquals("User roles are not defined", result.getMessages().get(0));
    }

    @Test
    @DisplayName("hasRole should return failed AuthResult when principal is null")
    void hasRoleWhenPrincipalIsNull() {
        AuthResult resultNullPrincipal = authorizationService.hasRole(null, "admin");
        assertFalse(resultNullPrincipal.isSuccess());
        assertTrue(resultNullPrincipal.hasMessages());
        assertFalse(resultNullPrincipal.hasExceptions());
        assertEquals("Authentication principal cannot be null", resultNullPrincipal.getMessages().get(0));
    }

    @Test
    @DisplayName("hasRole should return failed AuthResult when role is null")
    void hasRoleWhenRoleIsNull() {
        AuthResult resultNullRole = authorizationService.hasRole(principal, null);
        assertFalse(resultNullRole.isSuccess());
        assertTrue(resultNullRole.hasMessages());
        assertFalse(resultNullRole.hasExceptions());
        assertEquals("Role cannot be null", resultNullRole.getMessages().get(0));
    }

    @Test
    @DisplayName("hasRole should return failed AuthResult when role is empty")
    void hasRoleWhenRoleIsEmpty() {
        AuthResult resultNullRole = authorizationService.hasRole(principal, "");
        assertFalse(resultNullRole.isSuccess());
        assertTrue(resultNullRole.hasMessages());
        assertFalse(resultNullRole.hasExceptions());
        assertEquals("Role cannot be empty", resultNullRole.getMessages().get(0));
    }

    //============================== hasAllRoles tests =========================================

    @Test
    @DisplayName("hasAllRoles should return successful AuthResult when user has all roles from list")
    void hasAllRolesWhenUserHasAllRoles() {
        principal.setRoles(Set.of("admin", "user", "guest", "editor"));

        AuthResult result = authorizationService.hasAllRoles(principal, Set.of("user", "editor"));
        assertTrue(result.isSuccess());
        assertTrue(result.hasMessages());
        assertFalse(result.hasExceptions());
        assertEquals("User has all required roles", result.getMessages().get(0));
    }

    @Test
    @DisplayName("hasAllRoles should return failed AuthResult when user missing some roles")
    void hasAllRolesWhenMissRole() {
        principal.setRoles(Set.of("admin", "user", "editor"));

        AuthResult result = authorizationService.hasAllRoles(principal, Set.of("guest", "editor"));
        assertFalse(result.isSuccess());
        assertTrue(result.hasMessages());
        assertFalse(result.hasExceptions());
        assertEquals("User does not have all required roles", result.getMessages().get(0));
    }

    @Test
    @DisplayName("hasAllRoles should return failed AuthResult when roles collection is null")
    void hasAllRolesWhenCollectionIsNull() {
        principal.setRoles(Set.of("admin", "user"));

        AuthResult result = authorizationService.hasAllRoles(principal, null);
        assertFalse(result.isSuccess());
        assertTrue(result.hasMessages());
        assertFalse(result.hasExceptions());
        assertEquals("Roles collection cannot be null", result.getMessages().get(0));
    }

    @Test
    @DisplayName("hasAllRoles should return failed AuthResult when roles collection is empty")
    void hasAllRolesWhenCollectionIsEmpty() {
        principal.setRoles(Set.of());

        AuthResult result = authorizationService.hasAllRoles(principal, Set.of());
        assertFalse(result.isSuccess());
        assertTrue(result.hasMessages());
        assertFalse(result.hasExceptions());
        assertEquals("Empty roles collection - no roles to check", result.getMessages().get(0));
    }

    @Test
    @DisplayName("hasAllRoles should return failed AuthResult when principal is null")
    void hasAllRolesWhenPrincipalIsNull() {
        principal.setRoles(null);

        AuthResult resultNullPrincipal = authorizationService.hasAllRoles(null, Set.of("admin", "editor"));
        assertFalse(resultNullPrincipal.isSuccess());
        assertTrue(resultNullPrincipal.hasMessages());
        assertFalse(resultNullPrincipal.hasExceptions());
        assertEquals("Authentication principal cannot be null", resultNullPrincipal.getMessages().get(0));
    }

    @Test
    @DisplayName("hasAllRoles should return failed AuthResult when principal roles is null")
    void hasAllRolesWhenRolesIsNull() {
        principal.setRoles(null);

        AuthResult resultNullRoles = authorizationService.hasAllRoles(principal, Set.of("admin", "editor"));
        assertFalse(resultNullRoles.isSuccess());
        assertTrue(resultNullRoles.hasMessages());
        assertFalse(resultNullRoles.hasExceptions());
        assertEquals("User roles are not defined", resultNullRoles.getMessages().get(0));
    }

    //=============================== hasAnyRole tests =========================================

    @Test
    @DisplayName("hasAnyRole should return successful AuthResult when user has at least one role from list")
    void hasAnyRoleWhenUserHasAtLeastOneRole() {
        principal.setRoles(Set.of("admin", "user", "guest", "editor"));

        AuthResult result = authorizationService.hasAnyRole(principal, Set.of("moderator", "user"));
        assertTrue(result.isSuccess());
        assertTrue(result.hasMessages());
        assertFalse(result.hasExceptions());
        assertEquals("User has at least one required role", result.getMessages().get(0));
    }

    @Test
    @DisplayName("hasAnyRole should return failed AuthResult when user has none roles of the list")
    void hasAnyRoleWhenUserHasNoRoles() {
        principal.setRoles(Set.of("admin"));

        AuthResult result = authorizationService.hasAnyRole(principal, Set.of("user", "guest"));
        assertFalse(result.isSuccess());
        assertTrue(result.hasMessages());
        assertFalse(result.hasExceptions());
        assertEquals("User does not have any of the required roles", result.getMessages().get(0));
    }

    @Test
    @DisplayName("hasAnyRole should return failed AuthResult when roles collection is empty")
    void hasAnyRoleWhenCollectionIsEmpty() {
        principal.setRoles(Set.of("admin"));

        AuthResult result = authorizationService.hasAnyRole(principal, Set.of());
        assertFalse(result.isSuccess());
        assertTrue(result.hasMessages());
        assertFalse(result.hasExceptions());
        assertEquals("Roles collection is empty", result.getMessages().get(0));
    }

    @Test
    @DisplayName("hasAnyRole should return failed AuthResult when user roles is null")
    void hasAnyRoleWhenUserRolesIsNull() {
        principal.setRoles(null);

        AuthResult result = authorizationService.hasAnyRole(principal, Set.of("admin", "user"));
        assertFalse(result.isSuccess());
        assertTrue(result.hasMessages());
        assertFalse(result.hasExceptions());
        assertEquals("User roles are not defined", result.getMessages().get(0));
    }

    @Test
    @DisplayName("hasAnyRole should return failed AuthResult when roles collection is null")
    void hasAnyRoleWhenCollectionIsNull() {
        principal.setRoles(Set.of("admin"));

        AuthResult result = authorizationService.hasAnyRole(principal, null);
        assertFalse(result.isSuccess());
        assertTrue(result.hasMessages());
        assertFalse(result.hasExceptions());
        assertEquals("Roles collection cannot be null", result.getMessages().get(0));
    }

    @Test
    @DisplayName("hasAnyRole should return failed AuthResult when principal is null")
    void hasAnyRoleWhenPrincipalIsNull() {
        AuthResult result = authorizationService.hasAnyRole(null, Set.of("admin", "user"));
        assertFalse(result.isSuccess());
        assertTrue(result.hasMessages());
        assertFalse(result.hasExceptions());
        assertEquals("Authentication principal cannot be null", result.getMessages().get(0));
    }

    //========================== hasAnyRoles with count tests ===================================

    @Test
    @DisplayName("hasAnyRoles with count should return successful AuthResult when user has exactly required count")
    void hasAnyRolesWithCountWhenUserHasExactCount() {
        principal.setRoles(Set.of("admin", "user", "guest", "moderator", "editor"));
        int count = 2;

        AuthResult result = authorizationService.hasAnyRoles(principal, Set.of("admin", "profiler", "editor"), count);
        assertTrue(result.isSuccess());
        assertTrue(result.hasMessages());
        assertFalse(result.hasExceptions());
        assertEquals("User has at least " + count + " required roles", result.getMessages().get(0));
    }

    @Test
    @DisplayName("hasAnyRoles with count should return successful AuthResult when user has more than required count")
    void hasAnyRolesWithCountWhenUserHasMoreThanCount() {
        principal.setRoles(Set.of("admin", "user", "moderator"));
        int count = 1;

        AuthResult result = authorizationService.hasAnyRoles(principal, Set.of("admin", "user", "guest"), count);
        assertTrue(result.isSuccess());
        assertTrue(result.hasMessages());
        assertFalse(result.hasExceptions());
        assertEquals("User has at least " + count + " required roles", result.getMessages().get(0));
    }

    @Test
    @DisplayName("hasAnyRoles with count should return failed AuthResult when user has less than required count")
    void hasAnyRolesWithCountWhenUserHasLessThanCount() {
        principal.setRoles(Set.of("admin", "user"));
        int count = 2;
        int foundCount = 1;

        AuthResult result = authorizationService.hasAnyRoles(principal, Set.of("admin", "moderator", "editor"), count);
        assertFalse(result.isSuccess());
        assertTrue(result.hasMessages());
        assertFalse(result.hasExceptions());
        assertEquals("User has only " + foundCount + " of required " + count + " roles", result.getMessages().get(0));
    }

    @Test
    @DisplayName("hasAnyRoles with count should return successful AuthResult when count is 0")
    void hasAnyRolesWithCountWhenCountIsZero() {
        principal.setRoles(Set.of("admin"));

        AuthResult result = authorizationService.hasAnyRoles(principal, Set.of("guest"), 0);
        assertTrue(result.isSuccess());
        assertTrue(result.hasMessages());
        assertFalse(result.hasExceptions());
        assertEquals("Count is zero - no roles required", result.getMessages().get(0));
    }

    @Test
    @DisplayName("hasAnyRoles with count should return failed AuthResult when count is negative")
    void hasAnyRolesWithCountWhenCountIsNegative() {
        principal.setRoles(Set.of("admin"));
        int count = -1;

        AuthResult result = authorizationService.hasAnyRoles(principal, Set.of("guest"), count);
        assertFalse(result.isSuccess());
        assertTrue(result.hasMessages());
        assertFalse(result.hasExceptions());
        assertEquals("Count roles cannot be negative: " + count, result.getMessages().get(0));
    }

    @Test
    @DisplayName("hasAnyRoles with count should return failed AuthResult when user roles is null")
    void hasAnyRolesWithCountWhenUserRolesIsNull() {
        principal.setRoles(null);

        AuthResult result = authorizationService.hasAnyRoles(principal, Set.of("admin"), 1);
        assertFalse(result.isSuccess());
        assertTrue(result.hasMessages());
        assertFalse(result.hasExceptions());
        assertEquals("User roles are not defined", result.getMessages().get(0));
    }

    @Test
    @DisplayName("hasAnyRoles with count should return failed AuthResult when roles collection is null")
    void hasAnyRolesWithCountWhenCollectionIsNull() {
        principal.setRoles(Set.of("admin"));

        AuthResult result = authorizationService.hasAnyRoles(principal, null, 1);
        assertFalse(result.isSuccess());
        assertTrue(result.hasMessages());
        assertFalse(result.hasExceptions());
        assertEquals("Roles collections cannot be null", result.getMessages().get(0));
    }

    @Test
    @DisplayName("hasAnyRoles with count should return failed AuthResult when principal is null")
    void hasAnyRolesWithCountWhenPrincipalIsNull() {
        AuthResult result = authorizationService.hasAnyRoles(null, Set.of("admin"), 1);
        assertFalse(result.isSuccess());
        assertTrue(result.hasMessages());
        assertFalse(result.hasExceptions());
        assertEquals("Authentication principal cannot be null", result.getMessages().get(0));
    }

    //=============================== hasPermission tests =========================================

    @Test
    @DisplayName("hasPermission should return successful AuthResult when user has the permission")
    void hasPermissionWhenUserHasPermission() {
        principal.setPermissions(Set.of("read", "write"));
        String permission = "read";

        AuthResult result = authorizationService.hasPermission(principal, permission);
        assertTrue(result.isSuccess());
        assertTrue(result.hasMessages());
        assertFalse(result.hasExceptions());
        assertEquals("User has required permission: " + permission, result.getMessages().get(0));
    }

    @Test
    @DisplayName("hasPermission should return failed AuthResult when user doesn't have the permission")
    void hasPermissionWhenUserDoesNotHavePermission() {
        principal.setPermissions(Set.of("read"));
        String permission = "write";

        AuthResult result = authorizationService.hasPermission(principal, permission);
        assertFalse(result.isSuccess());
        assertTrue(result.hasMessages());
        assertFalse(result.hasExceptions());
        assertEquals("User does not have required permission: " + permission, result.getMessages().get(0));
    }

    @Test
    @DisplayName("hasPermission should return failed AuthResult when user permissions is null")
    void hasPermissionWhenUserPermissionsIsNull() {
        principal.setPermissions(null);

        AuthResult result = authorizationService.hasPermission(principal, "read");
        assertFalse(result.isSuccess());
        assertTrue(result.hasMessages());
        assertFalse(result.hasExceptions());
        assertEquals("User permissions are not defined", result.getMessages().get(0));
    }

    @Test
    @DisplayName("hasPermission should return failed AuthResult when principal is null")
    void hasPermissionWhenPrincipalIsNull() {
        AuthResult resultNullPrincipal = authorizationService.hasPermission(null, "read");
        assertFalse(resultNullPrincipal.isSuccess());
        assertTrue(resultNullPrincipal.hasMessages());
        assertFalse(resultNullPrincipal.hasExceptions());
        assertEquals("Authentication principal cannot be null", resultNullPrincipal.getMessages().get(0));
    }

    @Test
    @DisplayName("hasPermission should return failed AuthResult when permission is null")
    void hasPermissionWhenPermissionIsNull() {
        AuthResult resultNullPermission = authorizationService.hasPermission(principal, null);
        assertFalse(resultNullPermission.isSuccess());
        assertTrue(resultNullPermission.hasMessages());
        assertFalse(resultNullPermission.hasExceptions());
        assertEquals("Permission cannot be null", resultNullPermission.getMessages().get(0));
    }

    @Test
    @DisplayName("hasPermission should return failed AuthResult when permission is empty")
    void hasPermissionWhenPermissionIsEmpty() {
        AuthResult resultNullPermission = authorizationService.hasPermission(principal, "");
        assertFalse(resultNullPermission.isSuccess());
        assertTrue(resultNullPermission.hasMessages());
        assertFalse(resultNullPermission.hasExceptions());
        assertEquals("Permission cannot be empty", resultNullPermission.getMessages().get(0));
    }

    //=========================== hasAllPermissions tests ======================================

    @Test
    @DisplayName("hasAllPermissions should return successful AuthResult when user has all permissions from list")
    void hasAllPermissionsWhenUserHasAllPermissions() {
        principal.setPermissions(Set.of("read", "write", "delete", "change"));

        AuthResult result = authorizationService.hasAllPermissions(principal, Set.of("write", "delete"));
        assertTrue(result.isSuccess());
        assertTrue(result.hasMessages());
        assertFalse(result.hasExceptions());
        assertEquals("User has all required permissions", result.getMessages().get(0));
    }

    @Test
    @DisplayName("hasAllPermissions should return failed AuthResult when user missing some permissions")
    void hasAllPermissionsWhenMissPermission() {
        principal.setPermissions(Set.of("read", "write", "delete"));

        AuthResult result = authorizationService.hasAllPermissions(principal, Set.of("read", "change"));
        assertFalse(result.isSuccess());
        assertTrue(result.hasMessages());
        assertFalse(result.hasExceptions());
        assertEquals("User does not have all required permissions", result.getMessages().get(0));
    }

    @Test
    @DisplayName("hasAllPermissions should return failed AuthResult when permissions collection is null")
    void hasAllPermissionsWhenCollectionIsNull() {
        principal.setRoles(Set.of("read", "write"));

        AuthResult result = authorizationService.hasAllPermissions(principal, null);
        assertFalse(result.isSuccess());
        assertTrue(result.hasMessages());
        assertFalse(result.hasExceptions());
        assertEquals("Permissions collection cannot be null", result.getMessages().get(0));
    }

    @Test
    @DisplayName("hasAllPermissions should return failed AuthResult when permissions collection is empty")
    void hasAllPermissionsWhenCollectionIsEmpty() {
        principal.setRoles(Set.of("read", "write"));

        AuthResult result = authorizationService.hasAllPermissions(principal, Set.of());
        assertFalse(result.isSuccess());
        assertTrue(result.hasMessages());
        assertFalse(result.hasExceptions());
        assertEquals("Empty permissions collection - no permission to check", result.getMessages().get(0));
    }

    @Test
    @DisplayName("hasAllPermissions should return failed AuthResult when principal null")
    void hasAllPermissionsWhenPrincipalIsNull() {
        principal.setPermissions(null);

        AuthResult resultNullPrincipal = authorizationService.hasAllPermissions(null, Set.of("read", "write"));
        assertFalse(resultNullPrincipal.isSuccess());
        assertTrue(resultNullPrincipal.hasMessages());
        assertFalse(resultNullPrincipal.hasExceptions());
        assertEquals("Authentication principal cannot be null", resultNullPrincipal.getMessages().get(0));
    }

    @Test
    @DisplayName("hasAllPermissions should return failed AuthResult when user permissions is null")
    void hasAllPermissionsWhenUserPermissionsIsNull() {
        principal.setPermissions(null);

        AuthResult resultNullPermissions = authorizationService.hasAllPermissions(principal, Set.of("read", "write"));
        assertFalse(resultNullPermissions.isSuccess());
        assertTrue(resultNullPermissions.hasMessages());
        assertFalse(resultNullPermissions.hasExceptions());
        assertEquals("User permissions are not defined", resultNullPermissions.getMessages().get(0));
    }

    //============================ hasAnyPermission tests ======================================

    @Test
    @DisplayName("hasAnyPermission should return successful AuthResult when user has at least one permission from list")
    void hasAnyPermissionWhenUserHasAtLeastOnePermission() {
        principal.setPermissions(Set.of("read", "write", "delete"));

        AuthResult result = authorizationService.hasAnyPermission(principal, Set.of("write", "execute"));
        assertTrue(result.isSuccess());
        assertTrue(result.hasMessages());
        assertFalse(result.hasExceptions());
        assertEquals("User has at least one required permission", result.getMessages().get(0));
    }

    @Test
    @DisplayName("hasAnyPermission should return failed AuthResult when user has none permissions of the list")
    void hasAnyPermissionWhenUserHasNoPermissions() {
        principal.setPermissions(Set.of("read"));

        AuthResult result = authorizationService.hasAnyPermission(principal, Set.of("write", "execute"));
        assertFalse(result.isSuccess());
        assertTrue(result.hasMessages());
        assertFalse(result.hasExceptions());
        assertEquals("User does not have any of the required permissions", result.getMessages().get(0));
    }

    @Test
    @DisplayName("hasAnyPermission should return failed AuthResult when permissions collection is empty")
    void hasAnyPermissionWhenCollectionIsEmpty() {
        principal.setPermissions(Set.of("read"));

        AuthResult result = authorizationService.hasAnyPermission(principal, Set.of());
        assertFalse(result.isSuccess());
        assertTrue(result.hasMessages());
        assertFalse(result.hasExceptions());
        assertEquals("Permissions collection is empty", result.getMessages().get(0));
    }

    @Test
    @DisplayName("hasAnyPermission should return failed AuthResult when user permissions is null")
    void hasAnyPermissionWhenUserPermissionsIsNull() {
        principal.setPermissions(null);

        AuthResult result = authorizationService.hasAnyPermission(principal, Set.of("read", "write"));
        assertFalse(result.isSuccess());
        assertTrue(result.hasMessages());
        assertFalse(result.hasExceptions());
        assertEquals("User permissions are not defined", result.getMessages().get(0));
    }

    @Test
    @DisplayName("hasAnyPermission should return failed AuthResult when permissions collection is null")
    void hasAnyPermissionWhenCollectionIsNull() {
        principal.setPermissions(Set.of("read"));

        AuthResult result = authorizationService.hasAnyPermission(principal, null);
        assertFalse(result.isSuccess());
        assertTrue(result.hasMessages());
        assertFalse(result.hasExceptions());
        assertEquals("Permissions collection cannot be null", result.getMessages().get(0));
    }

    @Test
    @DisplayName("hasAnyPermission should return failed AuthResult when principal is null")
    void hasAnyPermissionWhenPrincipalIsNull() {
        AuthResult result = authorizationService.hasAnyPermission(null, Set.of("read", "write"));
        assertFalse(result.isSuccess());
        assertTrue(result.hasMessages());
        assertFalse(result.hasExceptions());
        assertEquals("Authentication principal cannot be null", result.getMessages().get(0));
    }

    //======================== hasAnyPermissions with count tests ================================

    @Test
    @DisplayName("hasAnyPermissions with count should return successful AuthResult when user has exactly required count")
    void hasAnyPermissionsWithCountWhenUserHasExactCount() {
        principal.setPermissions(Set.of("read", "write", "execute"));
        int count = 2;

        AuthResult result = authorizationService.hasAnyPermissions(principal, Set.of("read", "delete", "execute"), count);
        assertTrue(result.isSuccess());
        assertTrue(result.hasMessages());
        assertFalse(result.hasExceptions());
        assertEquals("User has at least " + count + " required permissions", result.getMessages().get(0));
    }

    @Test
    @DisplayName("hasAnyPermissions with count should return successful AuthResult when user has more than required count")
    void hasAnyPermissionsWithCountWhenUserHasMoreThanCount() {
        principal.setPermissions(Set.of("read", "write", "delete"));
        int count = 1;

        AuthResult result = authorizationService.hasAnyPermissions(principal, Set.of("execute", "read", "write"), count);
        assertTrue(result.isSuccess());
        assertTrue(result.hasMessages());
        assertFalse(result.hasExceptions());
        assertEquals("User has at least " + count + " required permissions", result.getMessages().get(0));
    }

    @Test
    @DisplayName("hasAnyPermissions with count should return failed AuthResult when user has less than required count")
    void hasAnyPermissionsWithCountWhenUserHasLessThanCount() {
        principal.setPermissions(Set.of("read", "write"));
        int count = 2;
        int foundCount = 1;

        AuthResult result = authorizationService.hasAnyPermissions(principal, Set.of("delete", "read", "execute"), count);
        assertFalse(result.isSuccess());
        assertTrue(result.hasMessages());
        assertFalse(result.hasExceptions());
        assertEquals("User has only " + foundCount + " of required " + count + " permissions",
                result.getMessages().get(0));
    }

    @Test
    @DisplayName("hasAnyPermissions with count should return successful AuthResult when count is 0")
    void hasAnyPermissionsWithCountWhenCountIsZero() {
        principal.setPermissions(Set.of("read"));

        AuthResult result = authorizationService.hasAnyPermissions(principal, Set.of("write"), 0);
        assertTrue(result.isSuccess());
        assertTrue(result.hasMessages());
        assertFalse(result.hasExceptions());
        assertEquals("Count is zero - no permissions required", result.getMessages().get(0));
    }

    @Test
    @DisplayName("hasAnyPermissions with count should return failed AuthResult when count is negative")
    void hasAnyPermissionsWithCountWhenCountIsNegative() {
        principal.setPermissions(Set.of("read"));
        int count = -1;

        AuthResult result = authorizationService.hasAnyPermissions(principal, Set.of("read"), count);
        assertFalse(result.isSuccess());
        assertTrue(result.hasMessages());
        assertFalse(result.hasExceptions());
        assertEquals("Count permissions cannot be negative: " + count, result.getMessages().get(0));
    }

    @Test
    @DisplayName("hasAnyPermissions with count should return failed AuthResult when user permissions is null")
    void hasAnyPermissionsWithCountWhenUserPermissionsIsNull() {
        principal.setPermissions(null);

        AuthResult result = authorizationService.hasAnyPermissions(principal, Set.of("read"), 1);
        assertFalse(result.isSuccess());
        assertTrue(result.hasMessages());
        assertFalse(result.hasExceptions());
        assertEquals("User permissions are not defined", result.getMessages().get(0));
    }

    @Test
    @DisplayName("hasAnyPermissions with count should return failed AuthResult when permissions collection is null")
    void hasAnyPermissionsWithCountWhenCollectionIsNull() {
        principal.setPermissions(Set.of("read"));

        AuthResult result = authorizationService.hasAnyPermissions(principal, null, 1);
        assertFalse(result.isSuccess());
        assertTrue(result.hasMessages());
        assertFalse(result.hasExceptions());
        assertEquals("Permissions collections cannot be null", result.getMessages().get(0));
    }

    @Test
    @DisplayName("hasAnyPermissions with count should return failed AuthResult when principal is null")
    void hasAnyPermissionsWithCountWhenPrincipalIsNull() {
        AuthResult result = authorizationService.hasAnyPermissions(null, Set.of("read"), 1);
        assertFalse(result.isSuccess());
        assertTrue(result.hasMessages());
        assertFalse(result.hasExceptions());
        assertEquals("Authentication principal cannot be null", result.getMessages().get(0));
    }

    //============================ hasRoleWithContext test ====================================

    @Test
    @DisplayName("hasRoleWithContext should work like hasRole and return successful AuthResult when user has the role")
    void hasRoleWithContextWhenUserHasRole() {
        principal.setRoles(Set.of("admin", "user", "guest"));
        String role = "admin";

        AuthResult result = authorizationService.hasRoleWithContext(principal, role, new Object());
        assertTrue(result.isSuccess());
        assertTrue(result.hasMessages());
        assertFalse(result.hasExceptions());
        assertEquals("User has required role: " + role, result.getMessages().get(0));
    }

    @Test
    @DisplayName("hasRoleWithContext should work like hasRole and return false when user doesn't have the role")
    void hasRoleWithContextWhenUserDoesNotHaveRole() {
        principal.setRoles(Set.of("user"));
        String role = "admin";

        AuthResult result = authorizationService.hasRoleWithContext(principal, "admin", new Object());
        assertFalse(result.isSuccess());
        assertTrue(result.hasMessages());
        assertFalse(result.hasExceptions());
        assertEquals("User does not have required role: " + role, result.getMessages().get(0));
    }

    @Test
    @DisplayName("hasRoleWithContext should work like hasRole and return failed AuthResult when user roles is null")
    void hasRoleWithContextWhenUserRolesIsNull() {
        principal.setRoles(null);

        AuthResult result = authorizationService.hasRoleWithContext(principal, "admin", new Object());
        assertFalse(result.isSuccess());
        assertTrue(result.hasMessages());
        assertFalse(result.hasExceptions());
        assertEquals("User roles are not defined", result.getMessages().get(0));
    }

    @Test
    @DisplayName("hasRoleWithContext should work like hasRole and return failed AuthResult when principal is null")
    void hasRoleWithContextWhenPrincipalIsNull() {
        AuthResult resultNullPrincipal = authorizationService.hasRoleWithContext(null, "admin", new Object());
        assertFalse(resultNullPrincipal.isSuccess());
        assertTrue(resultNullPrincipal.hasMessages());
        assertFalse(resultNullPrincipal.hasExceptions());
        assertEquals("Authentication principal cannot be null", resultNullPrincipal.getMessages().get(0));
    }

    @Test
    @DisplayName("hasRoleWithContext should work like hasRole and return failed AuthResult when role is null")
    void hasRoleWithContextWhenRoleIsNull() {
        AuthResult resultNullRole = authorizationService.hasRoleWithContext(principal, null, new Object());
        assertFalse(resultNullRole.isSuccess());
        assertTrue(resultNullRole.hasMessages());
        assertFalse(resultNullRole.hasExceptions());
        assertEquals("Role cannot be null", resultNullRole.getMessages().get(0));
    }

    @Test
    @DisplayName("hasRoleWithContext should work like hasRole and return failed AuthResult when role is empty")
    void hasRoleWithContextWhenRoleIsEmpty() {
        AuthResult resultNullEmpty = authorizationService.hasRoleWithContext(principal, "", new Object());
        assertFalse(resultNullEmpty.isSuccess());
        assertTrue(resultNullEmpty.hasMessages());
        assertFalse(resultNullEmpty.hasExceptions());
        assertEquals("Role cannot be empty", resultNullEmpty.getMessages().get(0));
    }

    @Test
    @DisplayName("hasRoleWithContext should work like hasRole no matter the context")
    void hasRoleWithContextDoesNotDependOnContext() {
        principal.setRoles(Set.of("admin", "user", "guest"));
        AuthResult resultObjectContextWithCorrectRole = authorizationService.hasRoleWithContext(principal, "admin", new Object());
        AuthResult resultObjectContextWithWrongRole = authorizationService.hasRoleWithContext(principal, "editor", new Object());
        AuthResult resultNullContextWithCorrectRole = authorizationService.hasRoleWithContext(principal, "admin", null);
        AuthResult resultNullContextWithWrongRole = authorizationService.hasRoleWithContext(principal, "editor", null);
        AuthResult resultOtherContextWithCorrectRole = authorizationService.hasRoleWithContext(principal, "admin", "context");
        AuthResult resultOtherContextWithWrongRole = authorizationService.hasRoleWithContext(principal, "editor", "context");
        assertTrue(resultObjectContextWithCorrectRole.isSuccess());
        assertFalse(resultObjectContextWithWrongRole.isSuccess());
        assertTrue(resultNullContextWithCorrectRole.isSuccess());
        assertFalse(resultNullContextWithWrongRole.isSuccess());
        assertTrue(resultOtherContextWithCorrectRole.isSuccess());
        assertFalse(resultOtherContextWithWrongRole.isSuccess());
    }

    //========================== hasPermissionWithContext test ==================================

    @Test
    @DisplayName("hasPermissionWithContext should work like hasPermission and return successful AuthResult when user has the permission")
    void hasPermissionWithContextWhenUserHasPermission() {
        principal.setPermissions(Set.of("read", "write", "delete"));
        String permission = "read";

        AuthResult result = authorizationService.hasPermissionWithContext(principal, permission, new Object());
        assertTrue(result.isSuccess());
        assertTrue(result.hasMessages());
        assertFalse(result.hasExceptions());
        assertEquals("User has required permission: " + permission, result.getMessages().get(0));
    }

    @Test
    @DisplayName("hasPermissionWithContext should work like hasPermission and return failed AuthResult when user doesn't have the permission")
    void hasPermissionWithContextWhenUserDoesNotHavePermission() {
        principal.setPermissions(Set.of("read"));
        String permission = "write";

        AuthResult result = authorizationService.hasPermissionWithContext(principal, permission, new Object());
        assertFalse(result.isSuccess());
        assertTrue(result.hasMessages());
        assertFalse(result.hasExceptions());
        assertEquals("User does not have required permission: " + permission, result.getMessages().get(0));
    }

    @Test
    @DisplayName("hasPermissionWithContext should work like hasPermission and return failed AuthResult when user permissions is null")
    void hasPermissionWithContextWhenUserPermissionsIsNull() {
        principal.setPermissions(null);

        AuthResult result = authorizationService.hasPermissionWithContext(principal, "read", new Object());
        assertFalse(result.isSuccess());
        assertTrue(result.hasMessages());
        assertFalse(result.hasExceptions());
        assertEquals("User permissions are not defined", result.getMessages().get(0));
    }

    @Test
    @DisplayName("hasPermissionWithContext should work like hasPermission and return failed AuthResult when principal is null")
    void hasPermissionWithContextWhenPrincipalIsNull() {
        AuthResult resultNullPrincipal = authorizationService.hasPermissionWithContext(null, "read", new Object());
        assertFalse(resultNullPrincipal.isSuccess());
        assertTrue(resultNullPrincipal.hasMessages());
        assertFalse(resultNullPrincipal.hasExceptions());
        assertEquals("Authentication principal cannot be null", resultNullPrincipal.getMessages().get(0));
    }

    @Test
    @DisplayName("hasPermissionWithContext should work like hasPermission and return false when permission is null")
    void hasPermissionWithContextWhenPermissionIsNull() {
        AuthResult resultNullPermission = authorizationService.hasPermissionWithContext(principal, null, new Object());
        assertFalse(resultNullPermission.isSuccess());
        assertTrue(resultNullPermission.hasMessages());
        assertFalse(resultNullPermission.hasExceptions());
        assertEquals("Permission cannot be null", resultNullPermission.getMessages().get(0));
    }

    @Test
    @DisplayName("hasPermissionWithContext should work like hasPermission and return false when permission is empty")
    void hasPermissionWithContextWhenPermissionIsEmpty() {
        AuthResult resultEmptyPermission = authorizationService.hasPermissionWithContext(principal, "", new Object());
        assertFalse(resultEmptyPermission.isSuccess());
        assertTrue(resultEmptyPermission.hasMessages());
        assertFalse(resultEmptyPermission.hasExceptions());
        assertEquals("Permission cannot be empty", resultEmptyPermission.getMessages().get(0));
    }

    @Test
    @DisplayName("hasPermissionWithContext should work like hasPermission no matter the context")
    void hasPermissionWithContextDoesNotDependOnContext() {
        principal.setPermissions(Set.of("read", "write", "execute"));
        AuthResult resultObjectContextWithCorrectPermission = authorizationService.hasPermissionWithContext(principal, "read", new Object());
        AuthResult resultObjectContextWithWrongPermission = authorizationService.hasPermissionWithContext(principal, "delete", new Object());
        AuthResult resultNullContextWithCorrectPermission = authorizationService.hasPermissionWithContext(principal, "read", null);
        AuthResult resultNullContextWithWrongPermission = authorizationService.hasPermissionWithContext(principal, "delete", null);
        AuthResult resultOtherContextWithCorrectPermission = authorizationService.hasPermissionWithContext(principal, "read", "context");
        AuthResult resultOtherContextWithWrongPermission = authorizationService.hasPermissionWithContext(principal, "delete", "context");
        assertTrue(resultObjectContextWithCorrectPermission.isSuccess());
        assertFalse(resultObjectContextWithWrongPermission.isSuccess());
        assertTrue(resultNullContextWithCorrectPermission.isSuccess());
        assertFalse(resultNullContextWithWrongPermission.isSuccess());
        assertTrue(resultOtherContextWithCorrectPermission.isSuccess());
        assertFalse(resultOtherContextWithWrongPermission.isSuccess());
    }
}
