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

    private void loadPasswords() {
        // TODO: Replace with loading passwords from file, you will want to add them to the passwords list defined above
        // TODO: Tips: Use buffered reader, make sure you split on separator, make sure you decrypt password
    }

    public PasswordModel() {
        loadPasswords();
    }

    static public boolean passwordFileExists() {
        return passwordFile.exists();
    }

    // If no passwords.txt file, sse password to create token and save in file with salt
    static public void initializePasswordFile(String password) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        passwordFile.createNewFile();

        // Generate random salt
        passwordFileSalt = generateRandomSalt();

        passwordFileKey = generateKeyFromPassword(password, passwordFileSalt);

        //Cipher cipher = Cipher.getInstance("AES");
        //SecretKeySpec key = new SecretKeySpec(encoded, "AES");
        //cipher.init(Cipher.ENCRYPT_MODE, key);
        //byte [] encryptedData = cipher.doFinal(verifyString.getBytes());

        String encryptedToken = encrypt(verifyString);
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

        int tabIndex = firstLine.indexOf(separator);
        if (tabIndex == -1) {
            System.out.println("Error: Invalid password file format");
            return false;
        }

        String salt = firstLine.substring(0, tabIndex);
        String encryptedToken = firstLine.substring(tabIndex + 1, firstLine.length());
        System.out.println("File read.\nSalt: " + salt + "\nToken: " + encryptedToken);

        byte[] saltBytes = Base64.getDecoder().decode(salt);

        byte[] encoded;
        try {
            encoded = generateKeyFromPassword(passwordFilePassword, saltBytes);
        }
        catch (NoSuchAlgorithmException e) {
            System.out.println("Error: Algorithm not found");
            return false;
        }
        catch (InvalidKeySpecException f){
            System.out.println("Error: Invalid key spec");
            return false;
        }

        Cipher cipher;
        SecretKeySpec key;
        try{
            cipher = Cipher.getInstance("AES");
            key = new SecretKeySpec(encoded, "AES");
        }
        catch (NoSuchAlgorithmException e){
            System.out.println("Error: Algorithm not found");
            return false;
        }
        catch (NoSuchPaddingException f){
            System.out.println("Error: No such padding found");
            return false;
        }

        // Decryption
        try{
            cipher.init(Cipher.DECRYPT_MODE, key);
        }
        catch (InvalidKeyException e){
            System.out.println("Error: Invalid key");
            return false;
        }
        byte [] decodedData = Base64.getDecoder().decode(encryptedToken);
        byte [] decryptedData;
        try{
            decryptedData = cipher.doFinal(decodedData);
        }
        catch (IllegalBlockSizeException e){
            System.out.println("Error: Illegal block size");
            return false;
        }
        catch (BadPaddingException e){
            System.out.println("Error: Bad padding");
            return false;
        }
        String token = new String(decryptedData);
        System.out.println("Decrypted token: " + token);

        if (token.equals(verifyString)){
            return true;
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

        // Replace original file with tmp file
        if (!passwordFile.delete()) {
            System.out.println("Error: Could not delete original passwords.txt");
            return;
        }
        if (!tmpFile.renameTo(passwordFile)) {
            System.out.println("Error: Could not rename tmp.txt to passwords.txt");
            return;
        }
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
                    bw.write(password.getLabel() + separator + encrypt(password.getPassword()));
                } else {
                    bw.write(line);
                }
                current++;
            }
        } catch (IOException e) {
            System.out.println("Error updating passwords.txt");
            return;
        }

        // Replace original file with tmp file
        if (!passwordFile.delete()) {
            System.out.println("Error: Could not delete original passwords.txt");
            return;
        }
        if (!tmpFile.renameTo(passwordFile)) {
            System.out.println("Error: Could not rename tmp.txt to passwords.txt");
            return;
        }
    }

    public void addPassword(Password password) {
        passwords.add(password);
        System.out.println("Added: " + passwords.getLast().getLabel());

        // Add new password to passwords.txt
        try {
            BufferedWriter bf = new BufferedWriter(new FileWriter(passwordFile, true));     // input true to FileWriter for append mode
            bf.append("\n" + passwords.getLast().getLabel() + separator + password.getPassword());
            bf.close();
        }
        catch (IOException e) {
            System.out.println("Error: Could not open passwords.txt");
            return;
        }
    }

    // TODO: Tip: Break down each piece into individual methods, for example: generateSalt(), encryptPassword, generateKey(), saveFile, etc ...
    // TODO: Use these functions above, and it will make it easier! Once you know encryption, decryption, etc works, you just need to tie them in

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

    static public String encrypt(String message){
        try{
            Cipher cipher = Cipher.getInstance("AES");
            SecretKeySpec key = new SecretKeySpec(passwordFileKey, "AES");
            
            cipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] encryptedData = cipher.doFinal(message.getBytes());

            String messageString = new String(Base64.getEncoder().encode(encryptedData));
            return messageString;
        }
        catch (NoSuchAlgorithmException e){
            return null;
        }
        catch (NoSuchPaddingException e){
            return null;
        }
        catch (InvalidKeyException e){
            return null;
        }
        catch (IllegalBlockSizeException e){
            return null;
        }
        catch (BadPaddingException e){
            return null;
        }
    }
}
