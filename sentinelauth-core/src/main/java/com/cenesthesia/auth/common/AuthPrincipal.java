package com.cenesthesia.auth.common;

import com.cenesthesia.auth.utils.PasswordSecurityUtils;

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
    private char[] id;
    /**Наименование пользователя в системе*/
    private char[] username;
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
     * @see AuthPrincipal#AuthPrincipal(char[])
     * @see AuthPrincipal#AuthPrincipal(char[], char[])
     * @see AuthPrincipal#AuthPrincipal(char[], char[], byte[], byte[])
     *
     * @param indf однозначный идентификатор пользователя
     */
    public AuthPrincipal(String indf) {
        this.id = indf.toCharArray();
        this.username = indf.toCharArray();
        this.passwordHash = new byte[0];
        this.salt = new byte[0];
    }

    /**
     * Минимальный конструктор для инициализации единого идентификатора пользователя
     * @see AuthPrincipal#AuthPrincipal(String)
     * @see AuthPrincipal#AuthPrincipal(String, String)
     * @see AuthPrincipal#AuthPrincipal(String, String, byte[], byte[])
     * @see AuthPrincipal#AuthPrincipal(char[], char[])
     * @see AuthPrincipal#AuthPrincipal(char[], char[], byte[], byte[])
     *
     * @param indf однозначный идентификатор пользователя
     */
    public AuthPrincipal(char[] indf) {
        this.id = indf;
        this.username = indf;
        this.passwordHash = new byte[0];
        this.salt = new byte[0];
    }

    /**
     * Конструктор для инициализации идентификатора пользователя
     * @see AuthPrincipal#AuthPrincipal(String)
     * @see AuthPrincipal#AuthPrincipal(String, String, byte[], byte[])
     * @see AuthPrincipal#AuthPrincipal(char[])
     * @see AuthPrincipal#AuthPrincipal(char[], char[])
     * @see AuthPrincipal#AuthPrincipal(char[], char[], byte[], byte[])
     *
     * @param id уникальный идентификатор пользователя
     * @param username наименование пользователя
     */
    public AuthPrincipal(String id, String username) {
        this.id = id.toCharArray();
        this.username = username.toCharArray();
        this.passwordHash = new byte[0];
        this.salt = new byte[0];
    }

    /**
     * Конструктор для инициализации идентификатора пользователя
     * @see AuthPrincipal#AuthPrincipal(String)
     * @see AuthPrincipal#AuthPrincipal(String, String)
     * @see AuthPrincipal#AuthPrincipal(String, String, byte[], byte[])
     * @see AuthPrincipal#AuthPrincipal(char[])
     * @see AuthPrincipal#AuthPrincipal(char[], char[], byte[], byte[])
     *
     * @param id уникальный идентификатор пользователя
     * @param username наименование пользователя
     */
    public AuthPrincipal(char[] id, char[] username) {
        this.id = id;
        this.username = username;
        this.passwordHash = new byte[0];
        this.salt = new byte[0];
    }

    /**
     * Конструктор для инициализации идентификатора и пароля пользователя
     * @see AuthPrincipal#AuthPrincipal(String)
     * @see AuthPrincipal#AuthPrincipal(String, String)
     * @see AuthPrincipal#AuthPrincipal(char[])
     * @see AuthPrincipal#AuthPrincipal(char[], char[])
     * @see AuthPrincipal#AuthPrincipal(char[], char[], byte[], byte[])
     *
     * @param id уникальный идентификатор пользователя
     * @param username наименование пользователя
     * @param passwordHash пароль
     * @param salt соль
     */
    public AuthPrincipal(String id, String username, byte[] passwordHash, byte[] salt) {
        this.id = id.toCharArray();
        this.username = username.toCharArray();
        this.passwordHash = passwordHash;
        this.salt = salt;
    }

    /**
     * Конструктор для инициализации идентификатора и пароля пользователя
     * @see AuthPrincipal#AuthPrincipal(String)
     * @see AuthPrincipal#AuthPrincipal(String, String)
     * @see AuthPrincipal#AuthPrincipal(String, String, byte[], byte[])
     * @see AuthPrincipal#AuthPrincipal(char[])
     * @see AuthPrincipal#AuthPrincipal(char[], char[])
     *
     * @param id уникальный идентификатор пользователя
     * @param username наименование пользователя
     * @param passwordHash пароль
     * @param salt соль
     */
    public AuthPrincipal(char[] id, char[] username, byte[] passwordHash, byte[] salt) {
        this.id = id;
        this.username = username;
        this.passwordHash = passwordHash;
        this.salt = salt;
    }

    /**
     * Возвращает уникальный идентификатор пользователя
     *
     * @return значение поля {@link AuthPrincipal#id}
     */
    public char[] getId() {
        return id;
    }

    /**
     * Устанавливает новый уникальный идентификатор пользователя.
     * В качестве меры безопасности предыдущее значение будет затерто.
     *
     * @param id новое значение для поля {@link AuthPrincipal#id}
     */
    public void setId(char[] id) {
        PasswordSecurityUtils.clearChars(this.id);
        this.id = id;
    }

    /**
     * Возвращает наименование пользователя в системе
     *
     * @return значение поля {@link AuthPrincipal#username}
     */
    public char[] getUsername() {
        return username;
    }

    /**
     * Устанавливает новое наименование пользователя в системе.
     * В качестве меры безопасности предыдущее значение будет затерто.
     *
     * @param username новое значение для поля {@link AuthPrincipal#username}
     */
    public void setUsername(char[] username) {
        PasswordSecurityUtils.clearChars(this.username);
        this.username = username;
    }

    /**
     * Возвращает пароль
     *
     * @return значение поля {@link AuthPrincipal#passwordHash}
     */
    public byte[] getPasswordHash() {
        return passwordHash;
    }

    /**
     * Устанавливает новый пароль.
     * В качестве меры безопасности предыдущее значение будет затерто.
     *
     * @param passwordHash новое значение для поля {@link AuthPrincipal#passwordHash}
     */
    public void setPasswordHash(byte[] passwordHash) {
        PasswordSecurityUtils.clearBytes(this.passwordHash);
        this.passwordHash = passwordHash;
    }

    /**
     * Возвращает соль
     *
     * @return значение поля {@link AuthPrincipal#salt}
     */
    public byte[] getSalt() {
        return salt;
    }

    /**
     * Устанавливает новую соль.
     * В качестве меры безопасности предыдущее значение будет затерто.
     *
     * @param salt значение для поля {@link AuthPrincipal#salt}
     */
    public void setSalt(byte[] salt) {
        PasswordSecurityUtils.clearBytes(this.salt);
        this.salt = salt;
    }

    /**
     * Возвращает множество ролей пользователя в системе
     *
     * @return значение поля {@link AuthPrincipal#roles}
     */
    public Set<String> getRoles() {
        return roles;
    }

    /**
     * Устанавливает новое множество ролей пользователя в системе.
     * В качестве меры безопасности предыдущее значение будет затерто.
     *
     * @param roles новое значение для поля {@link AuthPrincipal#roles}
     */
    public void setRoles(Set<String> roles) {
        clearRoles();
        this.roles = roles;
    }

    /**
     * Возвращает множество прав пользователя в системе
     *
     * @return значение поля {@link AuthPrincipal#permissions}
     */
    public Set<String> getPermissions() {
        return permissions;
    }

    /**
     * Устанавливает новое множество прав пользователя в системе.
     * В качестве меры безопасности предыдущее значение будет затерто.
     *
     * @param permissions новое значение для поля {@link AuthPrincipal#permissions}
     */
    public void setPermissions(Set<String> permissions) {
        clearPermission();
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
        this.permissions.clear();
    }
}
