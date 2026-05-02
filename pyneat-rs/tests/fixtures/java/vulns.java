// Test fixtures for Java security rules
// DO NOT use as templates!

import java.io.*;
import javax.crypto.*;

public class VulnerableCode {

    // Hardcoded Secrets
    private static final String API_KEY = "sk_live_abcdef1234567890abcdef1234567890";
    private static final String PASSWORD = "SuperSecret123!";

    // SQL Injection
    public void unsafeQuery(String userId) throws Exception {
        String query = "SELECT * FROM users WHERE id=" + userId;
        Statement stmt = connection.createStatement();
        ResultSet rs = stmt.executeQuery(query);
    }

    // Command Injection
    public void runCommand(String cmd) throws Exception {
        Runtime.getRuntime().exec(cmd);
        ProcessBuilder pb = new ProcessBuilder(userInput);
        pb.start();
    }

    // Path Traversal
    public String readFile(String filename) throws IOException {
        BufferedReader reader = new BufferedReader(new FileReader(userFilename));
        return reader.readLine();
    }

    // Weak Crypto
    public void weakCrypto() throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        Cipher des = Cipher.getInstance("DES");
    }

    // Debug statements
    public void processOrder(String order) {
        System.out.println("Processing order: " + order);
    }
}
