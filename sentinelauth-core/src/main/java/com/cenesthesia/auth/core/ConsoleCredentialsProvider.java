package com.cenesthesia.auth.core;

import com.cenesthesia.auth.api.ICredentialsProvider;
import com.cenesthesia.auth.common.Credentials;

import java.util.Scanner;

/**
 * Класс для считывания реквизитов аутентификации из консоли
 *
 * @author Cenesthesia
 * @version 1.0
 */
public class ConsoleCredentialsProvider implements ICredentialsProvider {
    @Override
    public Credentials provideCredentials() {
        Scanner scanner = new Scanner(System.in);
        System.out.print("Username: ");
        String username = scanner.nextLine();
        System.out.print("Password: ");
        String password = scanner.nextLine();

        return new Credentials(username, password.toCharArray());
    }
}
