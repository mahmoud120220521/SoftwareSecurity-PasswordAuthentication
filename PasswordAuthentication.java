
package passwordauthentication;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Scanner;

public class PasswordAuthentication {

    // Name: Mahmoud M AbdAlhadi
    // ID: 120220521

    static final String FILE_NAME = "users.txt";

    // Generate a random salt
    public static String generateSalt() {
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        return Base64.getEncoder().encodeToString(salt);
    }

    // Hash password using SHA-256
    public static String hashPassword(String password, String salt)
            throws Exception {

        String combined = password + salt;
        MessageDigest md = MessageDigest.getInstance("SHA-256");

        byte[] hash = md.digest(
                combined.getBytes(StandardCharsets.UTF_8));

        return Base64.getEncoder().encodeToString(hash);
    }

    // Check if username already exists
    public static boolean userExists(String username) throws Exception {

        File file = new File(FILE_NAME);
        if (!file.exists()) {
            return false;
        }

        BufferedReader reader = new BufferedReader(new FileReader(file));
        String line;

        while ((line = reader.readLine()) != null) {
            String[] data = line.split(":", 3);

            if (data.length == 3 && data[0].equals(username)) {
                reader.close();
                return true;
            }
        }

        reader.close();
        return false;
    }

    // Register a new user
    public static void register(String username, String password)
            throws Exception {

        if (username.isEmpty() || username.contains(":")
                || username.contains("\n") || username.contains("\r")
                || password.isEmpty()) {
            System.out.println("Invalid username or password.");
            return;
        }

        if (userExists(username)) {
            System.out.println("Username already exists.");
            return;
        }

        String salt = generateSalt();
        String hash = hashPassword(password, salt);

        FileWriter writer = new FileWriter(FILE_NAME, true);
        writer.write(username + ":" + salt + ":" + hash
                + System.lineSeparator());
        writer.close();

        System.out.println("Registration successful!");
    }

    // Login and verify password
    public static void login(String username, String password)
            throws Exception {

        File file = new File(FILE_NAME);

        if (!file.exists()) {
            System.out.println("Invalid username or password.");
            return;
        }

        BufferedReader reader = new BufferedReader(new FileReader(file));
        String line;

        while ((line = reader.readLine()) != null) {
            String[] data = line.split(":", 3);

            if (data.length == 3 && data[0].equals(username)) {

                String salt = data[1];
                String storedHash = data[2];
                String enteredHash = hashPassword(password, salt);

                reader.close();

                if (MessageDigest.isEqual(
                        storedHash.getBytes(StandardCharsets.UTF_8),
                        enteredHash.getBytes(StandardCharsets.UTF_8))) {
                    System.out.println("Login successful!");
                } else {
                    System.out.println("Invalid username or password.");
                }
                return;
            }
        }

        reader.close();
        System.out.println("Invalid username or password.");
    }

    public static void main(String[] args) throws Exception {

        Scanner input = new Scanner(System.in);

        while (true) {

            System.out.println("\n1. Register");
            System.out.println("2. Login");
            System.out.println("3. Exit");
            System.out.print("Choose: ");

            String choice = input.nextLine();

            if (choice.equals("3")) {
                System.out.println("Goodbye!");
                break;
            }

            if (choice.equals("1") || choice.equals("2")) {

                System.out.print("Username: ");
                String username = input.nextLine();

                System.out.print("Password: ");
                String password = input.nextLine();

                if (choice.equals("1")) {
                    register(username, password);
                } else {
                    login(username, password);
                }

            } else {
                System.out.println("Invalid choice.");
            }
        }

        input.close();
    }
}
