package edu.cwru.passwordmanager.model;

import javafx.collections.FXCollections;
import javafx.collections.ObservableList;

import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.Scanner;


public class PasswordModel {
    private ObservableList<Password> passwords = FXCollections.observableArrayList();

    // !!! DO NOT CHANGE - VERY IMPORTANT FOR GRADING !!!
    static private File passwordFile = new File("passwords.txt");

    static private String separator = "\t";

    static private String passwordFilePassword = "";
    static private byte [] passwordFileKey;
    static private byte [] passwordFileSalt;

    private static String verifyString = "cookies";

    public PasswordModel() {
        loadPasswords();
    }

    static public boolean passwordFileExists() {
        return passwordFile.exists();
    }

    private void loadPasswords() {
        if (!passwordFile.exists()) {
            return;
        }

        try (BufferedReader br = new BufferedReader(new FileReader(passwordFile))) {
            // Read first line that has salt and token
            String firstLine = br.readLine();
            if (firstLine == null) {
                return;
            }

            String encodedSalt = parseFirstLine(firstLine)[0];
            passwordFileSalt = Base64.getDecoder().decode(encodedSalt);

            // Generate key from provided master password
            try {
                passwordFileKey = generateKeyFromPassword(passwordFilePassword, passwordFileSalt);
            } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                System.out.println("Error generating key from password: " + e.getMessage());
                return;
            }

            // Read remaining lines
            String line;
            while ((line = br.readLine()) != null) {
                if (line.trim().isEmpty()) continue;

                String[] parts = line.split(separator, 2);
                String label = parts.length > 0 ? parts[0] : "";
                String encryptedPassword = parts.length > 1 ? parts[1] : "";

                String decryptedPassword = decrypt(encryptedPassword, passwordFileKey);

                passwords.add(new Password(label, decryptedPassword));
            }

        } catch (IOException e) {
            System.out.println("Error loading passwords.txt: " + e.getMessage());
        }
    }

    // If no passwords.txt file, sse password to create token and save in file with salt
    static public void initializePasswordFile(String password) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        passwordFile.createNewFile();

        // Generate random salt
        passwordFileSalt = generateRandomSalt();

        passwordFileKey = generateKeyFromPassword(password, passwordFileSalt);

        passwordFilePassword = password;

        String encryptedToken = encrypt(verifyString, passwordFileKey);
        System.out.println("Generated token: " + encryptedToken);

        BufferedWriter bf = new BufferedWriter(new FileWriter(passwordFile));
        bf.write(Base64.getEncoder().encodeToString(passwordFileSalt) + separator + encryptedToken);
        bf.close();
    }

    static public boolean verifyPassword(String password) {
        passwordFilePassword = password; // DO NOT CHANGE
        String firstLine = "";

        try (Scanner scn = new Scanner(passwordFile)){
            firstLine = scn.nextLine();
        }
        catch (FileNotFoundException e){
            System.out.println("Error: Could not read file passwords.txt");
        }

        String salt = parseFirstLine(firstLine)[0];
        String encryptedToken = parseFirstLine(firstLine)[1];
        System.out.println("File read.\nSalt: " + salt + "\nToken: " + encryptedToken);

        byte[] saltBytes = Base64.getDecoder().decode(salt);

        try {
            byte[] fileKey = generateKeyFromPassword(passwordFilePassword, saltBytes);

            String token = decrypt(encryptedToken, fileKey);
            System.out.println("Decrypted token: " + token);

            if (token == null) {
                return false;
            }
            else if (token.equals(verifyString)) {
                return true;    // Return true only if token can be decrypted with password
            }
        }
        catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            System.out.println("Error: Could not generate key from password.");
            return false;
        }

        return false;
    }

    public ObservableList<Password> getPasswords() {
        return passwords;
    }

    public void deletePassword(int index) {
        passwords.remove(index);

        // Use a temporary file to make changes
        File tmpFile = new File("tmp.txt");

        try (BufferedReader br = new BufferedReader(new FileReader(passwordFile));
             BufferedWriter bw = new BufferedWriter(new FileWriter(tmpFile))) {

            // First line is always salt and token, so copy as is
            String firstLine = br.readLine();
            if (firstLine != null) {
                bw.write(firstLine);
            }

            // Update line by line
            String line;
            int current = 0;
            while ((line = br.readLine()) != null) {
                if (current != index) {
                    bw.newLine();
                    bw.write(line);
                }
                current++;
            }
        } catch (IOException e) {
            System.out.println("Error updating passwords.txt");
            return;
        }

        replaceFile(passwordFile, tmpFile);
    }

    public void updatePassword(Password password, int index) {
        passwords.set(index, password);
        System.out.println("Updated: " + password.toString() + ", index: " + index);

        // Use a temporary file to make changes
        File tmpFile = new File("tmp.txt");

        try (BufferedReader br = new BufferedReader(new FileReader(passwordFile));
             BufferedWriter bw = new BufferedWriter(new FileWriter(tmpFile))) {

            // First line is always salt and token, so copy as is
            String firstLine = br.readLine();
            if (firstLine != null) {
                bw.write(firstLine);
            }

            // Update line by line
            String line;
            int current = 0;
            while ((line = br.readLine()) != null) {
                bw.newLine();
                if (current == index) {
                    bw.write(password.getLabel() + separator + encrypt(password.getPassword(), passwordFileKey));
                } else {
                    bw.write(line);
                }
                current++;
            }
        } catch (IOException e) {
            System.out.println("Error updating passwords.txt");
            return;
        }

        replaceFile(passwordFile, tmpFile);
    }

    public void addPassword(Password password) {
        passwords.add(password);
        System.out.println("Added: " + passwords.getLast().getLabel());

        // Add new password to passwords.txt
        try (BufferedWriter bf = new BufferedWriter(new FileWriter(passwordFile, true));) {
            bf.append("\n" + passwords.getLast().getLabel() + separator + password.getPassword());
        }
        catch (IOException e) {
            System.out.println("Error: Could not open passwords.txt");
            return;
        }
    }

    // Generates a random 16-byte salt from random bytes
    static public byte[] generateRandomSalt() {
        // String salt = Base64.getEncoder().encodeToString("MsSmith".getBytes());
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        random.nextBytes(salt);

        System.out.println("Generated salt: " + Base64.getEncoder().encodeToString(salt));
        return salt;
    }

    // Generate a key from a password using PBKDF2
    static private byte[] generateKeyFromPassword(String password, byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 600000, 256);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        SecretKey privateKey = factory.generateSecret(spec);
        return privateKey.getEncoded();
    }

    static public String encrypt(String message, byte[] encryptKey){
        try{
            Cipher cipher = Cipher.getInstance("AES");
            SecretKeySpec key = new SecretKeySpec(encryptKey, "AES");
            
            cipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] encryptedData = cipher.doFinal(message.getBytes());

            String messageString = new String(Base64.getEncoder().encode(encryptedData));
            return messageString;
        }
        catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException |
               IllegalBlockSizeException | BadPaddingException e) {
            System.out.println("Error: Could not encrypt.");
            return null;
        }
    }

    static public String decrypt(String ciphertext, byte[] key) {
        try {
            Cipher cipher = Cipher.getInstance("AES");
            SecretKeySpec cipherKey = new SecretKeySpec(key, "AES");

            cipher.init(Cipher.DECRYPT_MODE, cipherKey);
            byte[] decoded = Base64.getDecoder().decode(ciphertext);

            byte[] plain = cipher.doFinal(decoded);
            return new String(plain);
        }
        catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException |
               IllegalBlockSizeException | BadPaddingException e) {
            System.out.println("Error: Could not decrypt.");
            return null;
        }
    }

    // Deletes the old file and renames the new file to the old file's name
    public static void replaceFile(File oldFile, File newFile) {
        if (!oldFile.delete()) {
            System.out.println("Error: Could not delete original passwords.txt");
            return;
        }
        if (!newFile.renameTo(oldFile)) {
            System.out.println("Error: Could not rename tmp.txt to passwords.txt");
            return;
        }
    }

    // Reads the first line, if it exists in the right format, returns a String array where the first element is the salt
    // and the second is the token
    public static String[] parseFirstLine(String line) {
        int tabIndex = line.indexOf(separator);

        if (tabIndex == -1) {
            System.out.println("Error: Invalid password file format");
            return null;
        }

        String salt = line.substring(0, tabIndex);
        String token = line.substring(tabIndex + 1);

        return new String[]{salt, token};
    }
}
