package com.cenesthesia.auth.api;

import com.cenesthesia.auth.common.AuthPrincipal;

import java.util.Optional;

/**
 * Интерфейс источника информации об пользователях в системе
 *
 * @author Cenesthesia
 * @version 1.0
 */
public interface IAuthUserRepository {
    /**
     * Поиск пользователя по его наименования в системе. ! Важно: наименование
     * не гарантирует уникальность, если это не предусмотренно реализацией репозитория.
     * @see IAuthUserRepository#findById(String)
     * @see IAuthUserRepository#findBy(Object)
     *
     * @param username наименование пользователя в системе
     * @return пользователя с наименованием {@code username}, если такой существует, иначе null.
     * Возвращаемое значение обёрнуто в Optional.
     */
    Optional<AuthPrincipal> findByUsername(String username);

    /**
     * Поиск пользователя по его уникальному идентификатору
     * @see IAuthUserRepository#findByUsername(String)
     * @see IAuthUserRepository#findBy(Object)
     *
     * @param id уникальный идентификатор пользователя
     * @return пользователя с наименованием {@code username}, если такой существует, иначе null.
     * Возвращаемое значение обёрнуто в Optional.
     */
    Optional<AuthPrincipal> findById(String id);

    /**
     * Поиск пользователя по другому {@code obj} признаку. Заделка для кастомных репозиториев.
     * @see IAuthUserRepository#findByUsername(String)
     * @see IAuthUserRepository#findById(String)
     *
     * @param obj признак пользователя
     * @return пользователя с признаком {@code obj}, если такой существует, иначе null.
     * Возвращаемое значение обёрнуто в Optional.
     */
    default Optional<AuthPrincipal> findBy(Object obj) {
        return Optional.empty();
    }
}
