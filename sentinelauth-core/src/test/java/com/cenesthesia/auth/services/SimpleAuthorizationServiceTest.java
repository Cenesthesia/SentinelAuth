package com.cenesthesia.auth.services;

import com.cenesthesia.auth.api.IAuthorizationService;
import com.cenesthesia.auth.common.AuthPrincipal;
import com.cenesthesia.auth.core.SimpleAuthorizationService;
import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.util.Set;

@Tag("unit")
public class SimpleAuthorizationServiceTest {
    private IAuthorizationService authorizationService;
    private AuthPrincipal principal;

    @BeforeEach
    void setUp() {
        authorizationService = new SimpleAuthorizationService();
        principal = new AuthPrincipal("1", "testUser");
    }

    //=============================== hasRole tests ===========================================

    @Test
    @DisplayName("hasRole should return true when user has the role")
    void hasRoleWhenUserHasRole() {
        principal.setRoles(Set.of("admin", "user"));

        boolean result = authorizationService.hasRole(principal, "admin");
        assertTrue(result);
    }

    @Test
    @DisplayName("hasRole should return false when user doesn't have the role")
    void hasRoleWhenUserDoesNotHaveRole() {
        principal.setRoles(Set.of("user"));

        boolean result = authorizationService.hasRole(principal, "admin");
        assertFalse(result);
    }

    @Test
    @DisplayName("hasRole should return false when user roles is null")
    void hasRoleWhenUserRolesIsNull() {
        principal.setRoles(null);

        boolean result = authorizationService.hasRole(principal, "admin");
        assertFalse(result);
    }

    @Test
    @DisplayName("hasRole should return false when principal or role is null")
    void hasRoleWhenPrincipalOrRoleIsNull() {
        boolean resultNullPrincipal = authorizationService.hasRole(null, "admin");
        boolean resultNullRole = authorizationService.hasRole(principal, null);
        assertFalse(resultNullPrincipal);
        assertFalse(resultNullRole);
    }

    //============================== hasAllRoles tests =========================================

    @Test
    @DisplayName("hasAllRoles should return true when user has all roles from list")
    void hasAllRolesWhenUserHasAllRoles() {
        principal.setRoles(Set.of("admin", "user", "guest", "editor"));

        boolean result = authorizationService.hasAllRoles(principal, Set.of("user", "editor"));
        assertTrue(result);
    }

    @Test
    @DisplayName("hasAllRoles should return false when user missing some roles")
    void hasAllRolesWhenMissRole() {
        principal.setRoles(Set.of("admin", "user", "editor"));

        boolean result = authorizationService.hasAllRoles(principal, Set.of("guest", "editor"));
        assertFalse(result);
    }

    @Test
    @DisplayName("hasAllRoles should return false when roles collection is null")
    void hasAllRolesWhenCollectionIsNull() {
        principal.setRoles(Set.of("admin", "user"));

        boolean result = authorizationService.hasAllRoles(principal, null);
        assertFalse(result);
    }

    @Test
    @DisplayName("hasAllRoles should return false when principal or user roles is null")
    void hasAllRolesWhenPrincipalIsNull() {
        principal.setRoles(null);

        boolean resultNullPrincipal = authorizationService.hasAllRoles(null, Set.of("admin", "editor"));
        boolean resultNullRoles = authorizationService.hasAllRoles(principal, Set.of("admin", "editor"));
        assertFalse(resultNullPrincipal);
        assertFalse(resultNullRoles);
    }

    //=============================== hasAnyRole tests =========================================

    @Test
    @DisplayName("hasAnyRole should return true when user has at least one role from list")
    void hasAnyRoleWhenUserHasAtLeastOneRole() {
        principal.setRoles(Set.of("admin", "user", "guest", "editor"));

        boolean result = authorizationService.hasAnyRole(principal, Set.of("moderator", "user"));
        assertTrue(result);
    }

    @Test
    @DisplayName("hasAnyRole should return false when user has none roles of the list")
    void hasAnyRoleWhenUserHasNoRoles() {
        principal.setRoles(Set.of("admin"));

        boolean result = authorizationService.hasAnyRole(principal, Set.of("user", "guest"));
        assertFalse(result);
    }

    @Test
    @DisplayName("hasAnyRole should return false when roles collection is empty")
    void hasAnyRoleWhenCollectionIsEmpty() {
        principal.setRoles(Set.of("admin"));

        boolean result = authorizationService.hasAnyRole(principal, Set.of());
        assertFalse(result);
    }

    @Test
    @DisplayName("hasAnyRole should return false when user roles is null")
    void hasAnyRoleWhenUserRolesIsNull() {
        principal.setRoles(null);

        boolean result = authorizationService.hasAnyRole(principal, Set.of("admin", "user"));
        assertFalse(result);
    }

    @Test
    @DisplayName("hasAnyRole should return false when roles collection is null")
    void hasAnyRoleWhenCollectionIsNull() {
        principal.setRoles(Set.of("admin"));

        boolean result = authorizationService.hasAnyRole(principal, null);
        assertFalse(result);
    }

    @Test
    @DisplayName("hasAnyRole should return false when principal is null")
    void hasAnyRoleWhenPrincipalIsNull() {
        boolean result = authorizationService.hasAnyRole(null, Set.of("admin", "user"));
        assertFalse(result);
    }

    //========================== hasAnyRoles with count tests ===================================

    @Test
    @DisplayName("hasAnyRoles with count should return true when user has exactly required count")
    void hasAnyRolesWithCountWhenUserHasExactCount() {
        principal.setRoles(Set.of("admin", "user", "guest", "moderator", "editor"));

        boolean result = authorizationService.hasAnyRoles(principal, Set.of("admin", "profiler", "editor"), 2);
        assertTrue(result);
    }

    @Test
    @DisplayName("hasAnyRoles with count should return true when user has more than required count")
    void hasAnyRolesWithCountWhenUserHasMoreThanCount() {
        principal.setRoles(Set.of("admin", "user", "moderator"));

        boolean result = authorizationService.hasAnyRoles(principal, Set.of("admin", "user", "guest"), 1);
        assertTrue(result);
    }

    @Test
    @DisplayName("hasAnyRoles with count should return false when user has less than required count")
    void hasAnyRolesWithCountWhenUserHasLessThanCount() {
        principal.setRoles(Set.of("admin", "user"));

        boolean result = authorizationService.hasAnyRoles(principal, Set.of("admin", "moderator", "editor"), 2);
        assertFalse(result);
    }

    @Test
    @DisplayName("hasAnyRoles with count should return true when count is 0")
    void hasAnyRolesWithCountWhenCountIsZero() {
        principal.setRoles(Set.of("admin"));

        boolean result = authorizationService.hasAnyRoles(principal, Set.of("guest"), 0);
        assertTrue(result);
    }

    @Test
    @DisplayName("hasAnyRoles with count should throw exception when count is negative")
    void hasAnyRolesWithCountWhenCountIsNegative() {
        principal.setRoles(Set.of("admin"));
        assertThrows(IllegalArgumentException.class, () -> authorizationService.hasAnyRoles(principal, Set.of("guest"), -1));
    }

    @Test
    @DisplayName("hasAnyRoles with count should return false when user roles is null")
    void hasAnyRolesWithCountWhenUserRolesIsNull() {
        principal.setRoles(null);

        boolean result = authorizationService.hasAnyRoles(principal, Set.of("admin"), 1);
        assertFalse(result);
    }

    @Test
    @DisplayName("hasAnyRoles with count should return false when roles collection is null")
    void hasAnyRolesWithCountWhenCollectionIsNull() {
        principal.setRoles(Set.of("admin"));

        boolean result = authorizationService.hasAnyRoles(principal, null, 1);
        assertFalse(result);
    }

    @Test
    @DisplayName("hasAnyRoles with count should return false when principal is null")
    void hasAnyRolesWithCountWhenPrincipalIsNull() {
        boolean result = authorizationService.hasAnyRoles(null, Set.of("admin"), 1);
        assertFalse(result);
    }

    //=============================== hasPermission tests =========================================

    @Test
    @DisplayName("hasPermission should return true when user has the permission")
    void hasPermissionWhenUserHasPermission() {
        principal.setPermissions(Set.of("read", "write"));

        boolean result = authorizationService.hasPermission(principal, "read");
        assertTrue(result);
    }

    @Test
    @DisplayName("hasPermission should return false when user doesn't have the permission")
    void hasPermissionWhenUserDoesNotHavePermission() {
        principal.setPermissions(Set.of("read"));

        boolean result = authorizationService.hasPermission(principal, "write");
        assertFalse(result);
    }

    @Test
    @DisplayName("hasPermission should return false when user permissions is null")
    void hasPermissionWhenUserPermissionsIsNull() {
        principal.setPermissions(null);

        boolean result = authorizationService.hasPermission(principal, "read");
        assertFalse(result);
    }

    @Test
    @DisplayName("hasPermission should return false when principal or Permission is null")
    void hasRoleWhenPrincipalOrPermissionIsNull() {
        boolean resultNullPrincipal = authorizationService.hasPermission(null, "read");
        boolean resultNullPermission = authorizationService.hasPermission(principal, null);
        assertFalse(resultNullPrincipal);
        assertFalse(resultNullPermission);
    }

    //=========================== hasAllPermissions tests ======================================

    @Test
    @DisplayName("hasAllPermissions should return true when user has all permissions from list")
    void hasAllPermissionsWhenUserHasAllPermissions() {
        principal.setPermissions(Set.of("read", "write", "delete", "change"));

        boolean result = authorizationService.hasAllPermissions(principal, Set.of("write", "delete"));
        assertTrue(result);
    }

    @Test
    @DisplayName("hasAllPermissions should return false when user missing some permissions")
    void hasAllPermissionsWhenMissPermission() {
        principal.setPermissions(Set.of("read", "write", "delete"));

        boolean result = authorizationService.hasAllPermissions(principal, Set.of("read", "change"));
        assertFalse(result);
    }

    @Test
    @DisplayName("hasAllPermissions should return false when permissions collection is null")
    void hasAllPermissionsWhenCollectionIsNull() {
        principal.setRoles(Set.of("read", "write"));

        boolean result = authorizationService.hasAllPermissions(principal, null);
        assertFalse(result);
    }

    @Test
    @DisplayName("hasAllPermissions should return false when principal or user permissions is null")
    void hasAllPermissionsWhenPrincipalOrUserPermissionsIsNull() {
        principal.setPermissions(null);

        boolean resultNullPrincipal = authorizationService.hasAllPermissions(null, Set.of("read", "write"));
        boolean resultNullPermissions = authorizationService.hasAllPermissions(principal, Set.of("read", "write"));
        assertFalse(resultNullPrincipal);
        assertFalse(resultNullPermissions);
    }

    //============================ hasAnyPermission tests ======================================

    @Test
    @DisplayName("hasAnyPermission should return true when user has at least one permission from list")
    void hasAnyPermissionWhenUserHasAtLeastOnePermission() {
        principal.setPermissions(Set.of("read", "write", "delete"));

        boolean result = authorizationService.hasAnyPermission(principal, Set.of("write", "execute"));
        assertTrue(result);
    }

    @Test
    @DisplayName("hasAnyPermission should return false when user has none permissions of the list")
    void hasAnyPermissionWhenUserHasNoPermissions() {
        principal.setPermissions(Set.of("read"));

        boolean result = authorizationService.hasAnyPermission(principal, Set.of("write", "execute"));
        assertFalse(result);
    }

    @Test
    @DisplayName("hasAnyPermission should return false when permissions collection is empty")
    void hasAnyPermissionWhenCollectionIsEmpty() {
        principal.setPermissions(Set.of("read"));

        boolean result = authorizationService.hasAnyPermission(principal, Set.of());
        assertFalse(result);
    }

    @Test
    @DisplayName("hasAnyPermission should return false when user permissions is null")
    void hasAnyPermissionWhenUserPermissionsIsNull() {
        principal.setPermissions(null);

        boolean result = authorizationService.hasAnyPermission(principal, Set.of("read", "write"));
        assertFalse(result);
    }

    @Test
    @DisplayName("hasAnyPermission should return false when permissions collection is null")
    void hasAnyPermissionWhenCollectionIsNull() {
        principal.setPermissions(Set.of("read"));

        boolean result = authorizationService.hasAnyPermission(principal, null);
        assertFalse(result);
    }

    @Test
    @DisplayName("hasAnyPermission should return false when principal is null")
    void hasAnyPermissionWhenPrincipalIsNull() {
        boolean result = authorizationService.hasAnyPermission(null, Set.of("read", "write"));
        assertFalse(result);
    }

    //======================== hasAnyPermissions with count tests ================================

    @Test
    @DisplayName("hasAnyPermissions with count should return true when user has exactly required count")
    void hasAnyPermissionsWithCountWhenUserHasExactCount() {
        principal.setPermissions(Set.of("read", "write", "execute"));

        boolean result = authorizationService.hasAnyPermissions(principal, Set.of("read", "delete", "execute"), 2);
        assertTrue(result);
    }

    @Test
    @DisplayName("hasAnyPermissions with count should return true when user has more than required count")
    void hasAnyPermissionsWithCountWhenUserHasMoreThanCount() {
        principal.setPermissions(Set.of("read", "write", "delete"));

        boolean result = authorizationService.hasAnyPermissions(principal, Set.of("execute", "read", "write"), 1);
        assertTrue(result);
    }

    @Test
    @DisplayName("hasAnyPermissions with count should return false when user has less than required count")
    void hasAnyPermissionsWithCountWhenUserHasLessThanCount() {
        principal.setPermissions(Set.of("read", "write"));

        boolean result = authorizationService.hasAnyPermissions(principal, Set.of("delete", "read", "execute"), 2);
        assertFalse(result);
    }

    @Test
    @DisplayName("hasAnyPermissions with count should return true when count is 0")
    void hasAnyPermissionsWithCountWhenCountIsZero() {
        principal.setPermissions(Set.of("read"));

        boolean result = authorizationService.hasAnyPermissions(principal, Set.of("write"), 0);
        assertTrue(result);
    }

    @Test
    @DisplayName("hasAnyPermissions with count should throw exception when count is negative")
    void hasAnyPermissionsWithCountWhenCountIsNegative() {
        principal.setPermissions(Set.of("read"));
        assertThrows(IllegalArgumentException.class, () -> authorizationService.hasAnyPermissions(principal, Set.of("read"), -1));
    }

    @Test
    @DisplayName("hasAnyPermissions with count should return false when user permissions is null")
    void hasAnyPermissionsWithCountWhenUserPermissionsIsNull() {
        principal.setPermissions(null);

        boolean result = authorizationService.hasAnyPermissions(principal, Set.of("read"), 1);
        assertFalse(result);
    }

    @Test
    @DisplayName("hasAnyPermissions with count should return false when permissions collection is null")
    void hasAnyPermissionsWithCountWhenCollectionIsNull() {
        principal.setPermissions(Set.of("read"));

        boolean result = authorizationService.hasAnyPermissions(principal, null, 1);
        assertFalse(result);
    }

    @Test
    @DisplayName("hasAnyPermissions with count should return false when principal is null")
    void hasAnyPermissionsWithCountWhenPrincipalIsNull() {
        boolean result = authorizationService.hasAnyPermissions(null, Set.of("read"), 1);
        assertFalse(result);
    }

    //============================ hasRoleWithContext test ====================================

    @Test
    @DisplayName("hasRoleWithContext should work like hasRole and return true when user has the role")
    void hasRoleWithContextWhenUserHasRole() {
        principal.setRoles(Set.of("admin", "user", "guest"));

        boolean result = authorizationService.hasRoleWithContext(principal, "admin", new Object());
        assertTrue(result);
    }

    @Test
    @DisplayName("hasRoleWithContext should work like hasRole and return false when user doesn't have the role")
    void hasRoleWithContextWhenUserDoesNotHaveRole() {
        principal.setRoles(Set.of("user"));

        boolean result = authorizationService.hasRoleWithContext(principal, "admin", new Object());
        assertFalse(result);
    }

    @Test
    @DisplayName("hasRoleWithContext should work like hasRole and return false when user roles is null")
    void hasRoleWithContextWhenUserRolesIsNull() {
        principal.setRoles(null);

        boolean result = authorizationService.hasRoleWithContext(principal, "admin", new Object());
        assertFalse(result);
    }

    @Test
    @DisplayName("hasRoleWithContext should work like hasRole and return false when principal or role is null")
    void hasRoleWithContextWhenPrincipalOrRoleIsNull() {
        boolean resultNullPrincipal = authorizationService.hasRoleWithContext(null, "admin", new Object());
        boolean resultNullRole = authorizationService.hasRoleWithContext(principal, null, new Object());
        assertFalse(resultNullPrincipal);
        assertFalse(resultNullRole);
    }

    @Test
    @DisplayName("hasRoleWithContext should work like hasRole no matter the context")
    void hasRoleWithContextDoesNotDependOnContext() {
        principal.setRoles(Set.of("admin", "user", "guest"));
        boolean resultObjectContextWithCorrectRole = authorizationService.hasRoleWithContext(principal, "admin", new Object());
        boolean resultObjectContextWithWrongRole = authorizationService.hasRoleWithContext(principal, "editor", new Object());
        boolean resultNullContextWithCorrectRole = authorizationService.hasRoleWithContext(principal, "admin", null);
        boolean resultNullContextWithWrongRole = authorizationService.hasRoleWithContext(principal, "editor", null);
        boolean resultOtherContextWithCorrectRole = authorizationService.hasRoleWithContext(principal, "admin", "context");
        boolean resultOtherContextWithWrongRole = authorizationService.hasRoleWithContext(principal, "editor", "context");
        assertTrue(resultObjectContextWithCorrectRole);
        assertFalse(resultObjectContextWithWrongRole);
        assertTrue(resultNullContextWithCorrectRole);
        assertFalse(resultNullContextWithWrongRole);
        assertTrue(resultOtherContextWithCorrectRole);
        assertFalse(resultOtherContextWithWrongRole);
    }

    //========================== hasPermissionWithContext test ==================================

    @Test
    @DisplayName("hasPermissionWithContext should work like hasPermission and return true when user has the permission")
    void hasPermissionWithContextWhenUserHasPermission() {
        principal.setPermissions(Set.of("read", "write", "delete"));

        boolean result = authorizationService.hasPermissionWithContext(principal, "read", new Object());
        assertTrue(result);
    }

    @Test
    @DisplayName("hasPermissionWithContext should work like hasPermission and return false when user doesn't have the permission")
    void hasPermissionWithContextWhenUserDoesNotHavePermission() {
        principal.setPermissions(Set.of("read"));

        boolean result = authorizationService.hasPermissionWithContext(principal, "write", new Object());
        assertFalse(result);
    }

    @Test
    @DisplayName("hasPermissionWithContext should work like hasPermission and return false when user permissions is null")
    void hasPermissionWithContextWhenUserPermissionsIsNull() {
        principal.setPermissions(null);

        boolean result = authorizationService.hasPermissionWithContext(principal, "read", new Object());
        assertFalse(result);
    }

    @Test
    @DisplayName("hasPermissionWithContext should work like hasPermission and return false when principal or permission is null")
    void hasPermissionWithContextWhenPrincipalOrPermissionIsNull() {
        boolean resultNullPrincipal = authorizationService.hasPermissionWithContext(null, "read", new Object());
        boolean resultNullPermission = authorizationService.hasPermissionWithContext(principal, null, new Object());
        assertFalse(resultNullPrincipal);
        assertFalse(resultNullPermission);
    }

    @Test
    @DisplayName("hasPermissionWithContext should work like hasPermission no matter the context")
    void hasPermissionWithContextDoesNotDependOnContext() {
        principal.setPermissions(Set.of("read", "write", "execute"));
        boolean resultObjectContextWithCorrectPermission = authorizationService.hasPermissionWithContext(principal, "read", new Object());
        boolean resultObjectContextWithWrongPermission = authorizationService.hasPermissionWithContext(principal, "delete", new Object());
        boolean resultNullContextWithCorrectPermission = authorizationService.hasPermissionWithContext(principal, "read", null);
        boolean resultNullContextWithWrongPermission = authorizationService.hasPermissionWithContext(principal, "delete", null);
        boolean resultOtherContextWithCorrectPermission = authorizationService.hasPermissionWithContext(principal, "read", "context");
        boolean resultOtherContextWithWrongPermission = authorizationService.hasPermissionWithContext(principal, "delete", "context");
        assertTrue(resultObjectContextWithCorrectPermission);
        assertFalse(resultObjectContextWithWrongPermission);
        assertTrue(resultNullContextWithCorrectPermission);
        assertFalse(resultNullContextWithWrongPermission);
        assertTrue(resultOtherContextWithCorrectPermission);
        assertFalse(resultOtherContextWithWrongPermission);
    }
}
