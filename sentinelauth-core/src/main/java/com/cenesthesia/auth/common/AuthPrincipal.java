package com.cenesthesia.auth.common;

import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

//TODO: Подумать над инкапсуляцией, чтобы было невозможно извне менять сам класс пользователя

/**
 * Инкапсуляция данных пользователя
 *
 * @author Cenesthesia
 * @version 1.0
 */
public class AuthPrincipal {
    /**Уникальный идентификатор пользователя в системе (Зачастую аналогичен {@code username})*/
    private String id;
    /**Наименование пользователя в системе*/
    private String username;
    /**Хэш пароля*/
    private byte[] passwordHash;
    /**Соль*/
    private byte[] salt;
    /**Множество ролей в системе*/
    private Set<String> roles = new HashSet<>();
    /**Множество прав в системе*/
    private Set<String> permissions = new HashSet<>();

    /**
     * Минимальный конструктор для инициализации единого идентификатора пользователя
     * @see AuthPrincipal#AuthPrincipal(String, String)
     * @see AuthPrincipal#AuthPrincipal(String, String, byte[], byte[])
     *
     * @
     */
    public AuthPrincipal(String indf) {
        this.id = indf;
        this.username = indf;
        this.passwordHash = new byte[0];
        this.salt = new byte[0];
    }

    /**
     * Конструктор для инициализации идентификатора пользователя
     * @see AuthPrincipal#AuthPrincipal(String)
      *@see AuthPrincipal#AuthPrincipal(String, String, byte[], byte[])
     *
     * @param id уникальный идентификатор пользователя
     * @param username наименование пользователя
     */
    public AuthPrincipal(String id, String username) {
        this.id = id;
        this.username = username;
        this.passwordHash = new byte[0];
        this.salt = new byte[0];
    }

    /**
     * Конструктор для инициализации идентификатора и пароля пользователя
     * @see AuthPrincipal#AuthPrincipal(String)
     * @see AuthPrincipal#AuthPrincipal(String, String)
     *
     * @param id уникальный идентификатор пользователя
     * @param username наименование пользователя
     * @param passwordHash пароль
     * @param salt соль
     */
    public AuthPrincipal(String id, String username, byte[] passwordHash, byte[] salt) {
        this.id = id;
        this.username = username;
        this.passwordHash = passwordHash;
        this.salt = salt;
    }

    /**
     * Возвращает значение поля {@link AuthPrincipal#id}
     *
     * @return уникальный идентификатор пользователя
     */
    public String getId() {
        return id;
    }

    /**
     * Устанавливает значение для поля {@link AuthPrincipal#id}
     *
     * @param id новый уникальный идентификатор пользователя
     */
    public void setId(String id) {
        this.id = id;
    }

    /**
     * Возвращает значение поля {@link AuthPrincipal#username}
     *
     * @return наименование пользователя в системе
     */
    public String getUsername() {
        return username;
    }

    /**
     * Устанавливает значение для поля {@link AuthPrincipal#username}
     *
     * @param username наименование пользователя в системе
     */
    public void setUsername(String username) {
        this.username = username;
    }

    /**
     * Возвращает значение поля {@link AuthPrincipal#passwordHash}
     *
     * @return пароль
     */
    public byte[] getPasswordHash() {
        return passwordHash;
    }

    /**
     * Устанавливает значение для поля {@link AuthPrincipal#passwordHash}
     *
     * @param passwordHash пароль
     */
    public void setPasswordHash(byte[] passwordHash) {
        this.passwordHash = passwordHash;
    }

    /**
     * Возвращает значение поля {@link AuthPrincipal#salt}
     *
     * @return соль
     */
    public byte[] getSalt() {
        return salt;
    }

    /**
     * Устанавливает значение для поля {@link AuthPrincipal#salt}
     *
     * @param salt соль
     */
    public void setSalt(byte[] salt) {
        this.salt = salt;
    }

    /**
     * Возвращает значение поля {@link AuthPrincipal#roles}
     *
     * @return множество ролей пользователя в системе
     */
    public Set<String> getRoles() {
        return roles;
    }

    /**
     * Устанавливает значение для поля {@link AuthPrincipal#roles}
     *
     * @param roles множество ролей пользователя в системе
     */
    public void setRoles(Set<String> roles) {
        this.roles = roles;
    }

    /**
     * Возвращает значение поля {@link AuthPrincipal#permissions}
     *
     * @return множество прав пользователя в системе
     */
    public Set<String> getPermissions() {
        return permissions;
    }

    /**
     * Устанавливает значение для поля {@link AuthPrincipal#permissions}
     *
     * @param permissions множество прав пользователя в системе
     */
    public void setPermissions(Set<String> permissions) {
        this.permissions = permissions;
    }

    /**
     * Добавляет одну новую роль пользователю
     * @see AuthPrincipal#addAllRoles(Collection)
     *
     * @param role новая роль
     */
    public void addRole(String role) {
        this.roles.add(role);
    }

    /**
     * Добавляет несколько новых ролей пользователю
     * @see AuthPrincipal#addRole(String)
     *
     * @param roles новые роли
     */
    public void addAllRoles(Collection<String> roles) {
        this.roles.addAll(roles);
    }

    /**
     * Удаляет одну роль у пользователя
     * @see AuthPrincipal#removeAllRoles(Collection)
     *
     * @param role удаляемая роль
     */
    public void removeRole(String role) {
        this.roles.remove(role);
    }

    /**
     * Удаляет несколько ролей у пользователя
     * @see AuthPrincipal#removeRole(String)
     *
     * @param roles удаляемые роли
     */
    public void removeAllRoles(Collection<String> roles) {
        this.roles.removeAll(roles);
    }

    /**
     * Очищает все роли пользователя в системе
     */
    public void clearRoles() {
        this.roles.clear();
    }

    /**
     * Добавляет одно новое право пользователю
     * @see AuthPrincipal#addAllPermission(Collection)
     *
     * @param permission новое право
     */
    public void addPermission(String permission) {
        this.permissions.add(permission);
    }

    /**
     * Добавляет несколько новых прав пользователю
     * @see AuthPrincipal#addPermission(String)
     *
     * @param permissions новые права
     */
    public void addAllPermission(Collection<String> permissions) {
        this.permissions.addAll(permissions);
    }

    /**
     * Удаляет одно право у пользователя
     * @see AuthPrincipal#removeAllPermissions(Collection)
     *
     * @param permission удаляемое право
     */
    public void removePermission(String permission) {
        this.permissions.remove(permission);
    }

    /**
     * Удаляет несколько прав у пользователя
     * @see AuthPrincipal#removePermission(String)
     *
     * @param permissions удаляемые права
     */
    public void removeAllPermissions(Collection<String> permissions) {
        this.permissions.removeAll(permissions);
    }

    /**
     * Очищает все права пользователя в системе
     */
    public void clearPermission() {
        this.roles.clear();
    }
}
