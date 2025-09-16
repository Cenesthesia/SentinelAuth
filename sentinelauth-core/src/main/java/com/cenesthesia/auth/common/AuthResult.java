package com.cenesthesia.auth.common;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * Результат операций идентификации, аутентификации и авторизации
 * <p>
 * Унифицированный способ возврата результатов операций, позволяет клиенту получать детальную
 * информацию о результате операции (текстовые сообщения и исключения) вместо простого boolean значения.
 * </p>
 * @see AuthResult#builder(boolean);
 * @see AuthResultBuilder
 *
 * @author Cenesthesia
 * @version 1.0
 */
public class AuthResult {
    /**Успешность выполнения операции*/
    private final boolean success;
    /**Список текстовых сообщений, возникших во время выполнения операции*/
    private final List<String> messages;
    /**Список ошибок, возникших во время выполнения операции*/
    private final List<Exception> exceptions;

    /**
     * Конструктор - создает новый экземпляр {@link AuthResult} .
     *
     * @param success успешность выполнения операции
     * @param messages список текстовых сообщений (может быть null)
     * @param exceptions список исключений (может быть null)
     */
    private AuthResult(boolean success, List<String> messages, List<Exception> exceptions) {
        this.success = success;
        this.messages = messages != null ? messages : new ArrayList<>();
        this.exceptions = exceptions != null ? exceptions : new ArrayList<>();
    }

    /**
     * Создает успешный результат операции без дополнительных сообщений.
     * @see AuthResult#success(String)
     *
     * @return успешный {@link AuthResult}  без дополнительных сообщений
     */
    public static AuthResult success() {
        return new AuthResult(true, null, null);
    }

    /**
     * Создает успешный результат операции с текстовым сообщением.
     * @see AuthResult#success()
     *
     * @param message текстовое сообщение, возникшее во время выполнения операции
     * @return успешный {@link AuthResult}  с сообщением
     */
    public static AuthResult success(String message) {
        List<String> messages = new ArrayList<>();
        messages.add(message);
        return new AuthResult(true, messages, null);
    }

    /**
     * Создает неуспешный результат операции без дополнительной информации.
     * @see AuthResult#failure(String)
     * @see AuthResult#failure(Exception)
     * @see AuthResult#failure(String, Exception)
     *
     * @return неуспешный {@link AuthResult}
     */
    public static AuthResult failure() {
        return new AuthResult(false, null, null);
    }

    /**
     * Создает неуспешный результат операции с текстовым сообщением.
     * @see AuthResult#failure()
     * @see AuthResult#failure(Exception)
     * @see AuthResult#failure(String, Exception)
     *
     * @return неуспешный {@link AuthResult}  с сообщением
     */
    public static AuthResult failure(String message) {
        List<String> messages = new ArrayList<>();
        messages.add(message);
        return new AuthResult(false, messages, null);
    }

    /**
     * Создает неуспешный результат операции с исключением.
     * @see AuthResult#failure()
     * @see AuthResult#failure(String)
     * @see AuthResult#failure(String, Exception)
     *
     * @return неуспешный {@link AuthResult}  с исключением
     */
    public static AuthResult failure(Exception exception) {
        List<Exception> exceptions = new ArrayList<>();
        exceptions.add(exception);
        return new AuthResult(false, null, exceptions);
    }

    /**
     * Создает неуспешный результат операции с текстовым сообщением и исключением.
     * @see AuthResult#failure()
     * @see AuthResult#failure(String)
     * @see AuthResult#failure(Exception)
     *
     * @return неуспешный {@link AuthResult}  с сообщением и исключением
     */
    public static AuthResult failure(String message, Exception exception) {
        List<String> messages = new ArrayList<>();
        messages.add(message);
        List<Exception> exceptions = new ArrayList<>();
        exceptions.add(exception);
        return new AuthResult(false, messages, exceptions);
    }

    /**
     * Добавляет текстовое сообщение к текущему результату.
     * <p>
     * Создает новый экземпляр AuthResult с добавленным сообщением.
     * Исходный объект остается неизменным.
     * </p>
     * @see AuthResult#withMessages(Collection)
     *
     * @param message сообщение на добавление
     * @return новый {@link AuthResult} , на основе текущего, с добавленным сообщением
     */
    public AuthResult withMessage(String message) {
        List<String> newMessages = new ArrayList<>(this.messages);
        newMessages.add(message);
        return new AuthResult(this.success, newMessages, this.exceptions);
    }

    /**
     * Добавляет набор текстовых сообщений к текущему результату.
     * <p>
     * Создает новый экземпляр AuthResult с добавленными сообщениями.
     * Исходный объект остается неизменным.
     * </p>
     * @see AuthResult#withMessage(String)
     *
     * @param messages сообщения на добавление
     * @return новый {@link AuthResult} , на основе текущего, с добавленными сообщениями
     */
    public AuthResult withMessages(Collection<String> messages) {
        List<String> newMessages = new ArrayList<>(this.messages);
        newMessages.addAll(messages);
        return new AuthResult(this.success, newMessages, this.exceptions);
    }

    /**
     * Добавляет исключение к текущему результату.
     * <p>
     * Создает новый экземпляр AuthResult с добавленным исключением.
     * Исходный объект остается неизменным.
     * </p>
     * @see AuthResult#withException(Exception)
     *
     * @param exception исключение на добавление
     * @return новый AuthResult, на основе текущего, с добавленным исключением
     */
    public AuthResult withException(Exception exception) {
        List<Exception> newExceptions = new ArrayList<>(this.exceptions);
        newExceptions.add(exception);
        return new AuthResult(this.success, this.messages, newExceptions);
    }

    /**
     * Добавляет набор исключений к текущему результату.
     * <p>
     * Создает новый экземпляр AuthResult с добавленными исключениями.
     * Исходный объект остается неизменным.
     * </p>
     * @see AuthResult#withExceptions(Collection)
     *
     * @param exceptions исключения на добавление
     * @return новый AuthResult, на основе текущего, с добавленными исключениями
     */
    public AuthResult withExceptions(Collection<Exception> exceptions) {
        List<Exception> newExceptions = new ArrayList<>(this.exceptions);
        newExceptions.addAll(exceptions);
        return new AuthResult(this.success, this.messages, newExceptions);
    }

    /**
     * Проверяет, была ли операция успешной.
     *
     * @return true, если операция выполнена успешно, иначе false
     */
    public boolean isSuccess() {
        return success;
    }

    /**
     * Проверяет, содержит ли результат текстовые сообщения.
     *
     * @return true, если есть текстовые сообщения, иначе false
     */
    public boolean hasMessages() {
        return !messages.isEmpty();
    }

    /**
     * Возвращает список текстовых сообщений.
     * <p>
     * Возвращаемый список является копией внутреннего списка для обеспечения иммутабельности.
     * </p>
     *
     * @return копия списка текстовых сообщений
     */
    public List<String> getMessages() {
        return new ArrayList<>(messages);
    }

    /**
     * Проверяет наличие исключений в результате.
     *
     * @return true, если есть исключения, иначе false
     */
    public boolean hasExceptions() {
        return !exceptions.isEmpty();
    }

    /**
     * Возвращает список исключений.
     * <p>
     * Возвращаемый список является копией внутреннего списка для обеспечения иммутабельности.
     * </p>
     *
     * @return копия списка исключений
     */
    public List<Exception> getExceptions() {
        return new ArrayList<>(exceptions);
    }

    /**
     * Создает Builder для построения сложных результатов операций.
     * <p>
     * AuthResultBuilder позволяет эффективно создавать результаты с множеством сообщений и исключений
     * без многократного создания новых объектов.
     * </p>
     *
     * @param success успешность выполняемой операции
     * @return {@link AuthResultBuilder} для создания {@link AuthResult}
     */
    public static AuthResultBuilder builder(boolean success) {
        return new AuthResultBuilder(success);
    }

    /**
     * Builder для создания сложных результатов операций.
     * <p>
     * Позволяет эффективно создавать {@link AuthResult} с множеством сообщений и исключений.
     * </p>
     *
     * @see AuthResult
     * @see AuthResult#builder(boolean)
     *
     * @author Cenesthesia
     * @version 1.0
     */
    public static class AuthResultBuilder {
        /**Успешность выполнения операции*/
        private boolean success;
        /**Список текстовых сообщений, возникших во время выполнения операции*/
        private final List<String> messages = new ArrayList<>();
        /**Список ошибок, возникших во время выполнения операции*/
        private final List<Exception> exceptions = new ArrayList<>();

        /**
         * Конструктор - создает новый Builder с указанной {@code success} успешностью
         *
         * @param success успешность операции
         */
        private AuthResultBuilder(boolean success) {
            this.success = success;
        }

        /**
         * Изменяет статус успешности операции.
         *
         * @param success успешность операции
         * @return сам же объект {@link AuthResultBuilder} для цепочного вызова
         */
        public AuthResultBuilder changeSuccess(boolean success) {
            this.success = success;
            return this;
        }

        /**
         * Добавляет текстовое сообщение к результату.
         * @see AuthResultBuilder#messages(Collection)
         *
         * @param message текстовое сообщение
         * @return сам же объект {@link AuthResultBuilder} для цепочного вызова
         */
        public AuthResultBuilder message(String message) {
            this.messages.add(message);
            return this;
        }

        /**
         * Добавляет набор текстовых сообщений к результату.
         * @see AuthResultBuilder#message(String)
         *
         * @param messages набор текстовых сообщений
         * @return сам же объект {@link AuthResultBuilder} для цепочного вызова
         */
        public AuthResultBuilder messages(Collection<String> messages) {
            this.messages.addAll(messages);
            return this;
        }

        /**
         * Добавляет исключение к результату.
         * @see AuthResultBuilder#exceptions(Collection)
         *
         * @param exception исключение
         * @return сам же объект {@link AuthResultBuilder} для цепочного вызова
         */
        public AuthResultBuilder exception(Exception exception) {
            this.exceptions.add(exception);
            return this;
        }

        /**
         * Добавляет набор исключений к результату.
         * @see AuthResultBuilder#exception(Exception)
         *
         * @param exceptions набор исключение
         * @return сам же объект {@link AuthResultBuilder} для цепочного вызова
         */
        public AuthResultBuilder exceptions(Collection<Exception> exceptions) {
            this.exceptions.addAll(exceptions);
            return this;
        }

        /**
         * Добавляет информацию (текстовые сообщения и исключения) из {@code another} к создаваемому {@link AuthResult}.
         * <p>
         * Списки текстовых сообщений и исключений являются копиями {@code anothere} списков для обеспечения иммутабельности.
         * Передаваемый объект не изменяется.
         * </p>
         *
         * @param another другой
         * @return сам же объект {@link AuthResultBuilder} для цепочного вызова
         */
        public AuthResultBuilder basedOnAnother(AuthResult another) {
            this.success = another.success;
            this.messages.addAll(new ArrayList<>(another.messages));
            this.exceptions.addAll(new ArrayList<>(another.exceptions));
            return this;
        }

        /**
         * Создает экземпляр {@link AuthResult} на основе текущего состояния {@link AuthResultBuilder}
         *
         * @return новый экземпляр {@link AuthResult}
         */
        public AuthResult build() {
            return new AuthResult(this.success, this.messages, this.exceptions);
        }
    }
}
