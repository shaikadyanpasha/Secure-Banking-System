package coe817.project;

import javax.crypto.*;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Arrays;

// part 4
import java.util.Date;
import java.util.Map;
import java.util.HashMap;
import java.io.FileWriter;
import java.io.FileReader;
import java.io.BufferedReader;
import java.io.IOException;

// replay protection
import java.util.Set;
import java.util.HashSet;

//database
import coe817.project.DatabaseManager;


public class BankServer extends Thread{
    private final static SecretKey SharedKey = Encryption.convertToAESKey("fBhTxNXZ+fZbz2JOw8vqvtccdwjPShXUb0OF4E0wlWI=");
    private static SecretKey MasterSecret;
    private final Socket socket;
    //private static final ArrayList<User> USERS = new ArrayList<>();
    private User currentUser;

    // part 3
    private static SecretKey encryptionKey;
    private static SecretKey macKey;

    // part 4
    //private static final Map<String, Integer> balances = new HashMap<>();
    
    // replay protection
    private static final Set<String> usedNonces = new HashSet<>();
    private static final long MAX_TIME_DIFF_MS = 10_000; // 10 seconds

    static {
    DatabaseManager.initDB();
    }

    public BankServer(Socket socket) {
        super();
        this.socket = socket;

    }

    public void run(){
        try (
                PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
                BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        ) {
            boolean isContinue = true;
            while (isContinue) {
                //Operations LIST
                String[] socketMsg = Encryption.AESdecrypt(in.readLine(), SharedKey).strip().split(",");
                String option = socketMsg[0];
                System.out.println(Arrays.toString(socketMsg));
                switch (option) {
                    case "register" -> {
                        // REGISTER
                        String response = register(socketMsg);
                        out.println(response);
                    }
                    case "login" -> {
                        //LOGIN
                        String response = login(socketMsg);
                        out.println(response);
                        if (response.equals("LOGIN SUCCESSFUL")){
                            // AUTH USERS, GENERATE MASTER KEY
                            authProtocol(out, in);
                        }
                        if(MasterSecret!=null){
                            // IMPLEMENT (3)
                        }
                    }
                    case "deposit" -> {
                        String secureInput = in.readLine();
                        String[] secureParts = secureInput.split(",", 2);
                        String encryptedPayload = secureParts[0];
                        String receivedMAC = secureParts[1];

                        String decryptedPayload = Encryption.AESdecrypt(encryptedPayload, encryptionKey);
                        if (!Encryption.verifyMAC(decryptedPayload, receivedMAC, macKey)) {
                            out.println("MAC verification failed.");
                            break;
                        }

                        String[] parts = decryptedPayload.split(",");
                        String username = parts[0];
                        int amount = Integer.parseInt(parts[2]);
                        String timestamp = parts[3];
                        String nonce = parts[4];
                        if (isReplay(timestamp, nonce)) {
                            out.println("Replay attack detected. Transaction rejected.");
                            break;
                        }

                        // Optional debug
                        System.out.printf("Received Deposit: user=%s, amount=%s, time=%s, nonce=%s%n",username, amount, timestamp, nonce);

                        if (amount <= 0) {
                            String msg = "Invalid deposit amount.";
                            out.println(Encryption.AESencrypt(msg, encryptionKey) + "," + Encryption.generateMAC(msg, macKey));
                            break;
                        }

                        DatabaseManager.deposit(username, amount);
                        String response = "Deposit successful. Balance: " + DatabaseManager.getBalance(username);

                        logTransaction(username, "deposit"); // part 4 logging — placeholder

                        String encrypted = Encryption.AESencrypt(response, encryptionKey);
                        String mac = Encryption.generateMAC(response, macKey);
                        out.println(encrypted + "," + mac);
                    }
                    case "withdraw" -> {
                        String secureInput = in.readLine();
                        String[] secureParts = secureInput.split(",", 2);
                        String encryptedPayload = secureParts[0];
                        String receivedMAC = secureParts[1];

                        String decryptedPayload = Encryption.AESdecrypt(encryptedPayload, encryptionKey);
                        if (!Encryption.verifyMAC(decryptedPayload, receivedMAC, macKey)) {
                            out.println("MAC verification failed.");
                            break;
                        }

                        String[] parts = decryptedPayload.split(",");
                        String username = parts[0];
                        int amount = Integer.parseInt(parts[2]);
                        String timestamp = parts[3];
                        String nonce = parts[4];

                        if (isReplay(timestamp, nonce)) {
                            out.println("Replay attack detected. Transaction rejected.");
                            break;
                        }

                        // Optional debug
                        System.out.printf("Received Withdraw: user=%s, amount=%s, time=%s, nonce=%s%n",username, amount, timestamp, nonce);

                        if (amount <= 0) {
                            String msg = "Invalid withdrawal amount.";
                            out.println(Encryption.AESencrypt(msg, encryptionKey) + "," + Encryption.generateMAC(msg, macKey));
                            break;
                        }

                        boolean success = DatabaseManager.withdraw(username, amount);
                        String response = success
                            ? "Withdraw successful. Balance: " + DatabaseManager.getBalance(username)
                            : "Insufficient funds.";


                        logTransaction(username, "withdraw");

                        String encrypted = Encryption.AESencrypt(response, encryptionKey);
                        String mac = Encryption.generateMAC(response, macKey);
                        out.println(encrypted + "," + mac);
                    }
                    case "check_balance" -> {
                        String secureInput = in.readLine();
                        String[] secureParts = secureInput.split(",", 2);
                        String encryptedPayload = secureParts[0];
                        String receivedMAC = secureParts[1];

                        String decryptedPayload = Encryption.AESdecrypt(encryptedPayload, encryptionKey);
                        if (!Encryption.verifyMAC(decryptedPayload, receivedMAC, macKey)) {
                            out.println("MAC verification failed.");
                            break;
                        }

                        String[] parts = decryptedPayload.split(",");
                        String username = parts[0];
                        String timestamp = parts[2];
                        String nonce = parts[3];

                        if (isReplay(timestamp, nonce)) {
                            out.println("Replay attack detected. Request rejected.");
                            break;
                        }

                        System.out.printf("Received Balance Check: user=%s, time=%s, nonce=%s%n", username, timestamp, nonce);

                        int balance = DatabaseManager.getBalance(username);
                        String response = "Current balance: " + balance;

                        logTransaction(username, "check_balance");

                        String encrypted = Encryption.AESencrypt(response, encryptionKey);
                        String mac = Encryption.generateMAC(response, macKey);
                        out.println(encrypted + "," + mac);
                    }
                    case "logout" -> {
                        // LOGOUT
                        currentUser = null;
                        MasterSecret = null;
                        
                        // FOR DEBUGGING ONLY 
                        exportDecryptedAuditLog();
                        out.println("User logged out successfully.");
                    }
                    default -> System.out.println("Incorrect Option");
                }
            }
        } catch(Exception e){
            System.out.println(e);
        }
    }

    private String register(String[] msg) {
        System.out.println("\nRegistering User");

        if (msg.length != 3 || msg[1] == null || msg[2] == null || msg[1].isEmpty() || msg[2].isEmpty()) {
            System.out.println("REGISTERING FAILED: INVALID USERNAME/PASSWORD");
            return "REGISTERING FAILED: INVALID USERNAME/PASSWORD";
        }

        String username = msg[1];
        String password = msg[2];

        if (DatabaseManager.registerUser(username, password)) {
            System.out.printf("USER %s HAS REGISTERED%n", username);
            return "User Creation was Successful!";
        } else {
            System.out.printf("USER %s ALREADY EXISTS%n", username);
            return "REGISTERING FAILED: USERNAME TAKEN";
        }
    }

    private String login(String[] msg) {
        if (msg.length != 3 || msg[1] == null || msg[2] == null || msg[1].isEmpty() || msg[2].isEmpty()) {
            System.out.println("LOGIN FAILED: INVALID INPUT");
            return "LOGIN FAILED: INVALID INPUT";
        }

        String username = msg[1];
        String password = msg[2];

        if (DatabaseManager.verifyLogin(username, password)) {
            currentUser = new User(username, password);
            System.out.printf("USER [%s] HAS LOGGED IN%n", username);
            return "LOGIN SUCCESSFUL";
        } else {
            System.out.println("LOGIN FAILED");
            return "LOGIN FAILED";
        }
    }

    private void authProtocol(PrintWriter out, BufferedReader in) throws Exception{
        // SHOULD CREATE A MASTER KEY & VERIFY USER.
        // Step 1: Receive identity and nonce NA from client
        System.out.println("--------------------");
        String message1 = in.readLine();
        System.out.println(" Received Message 1: " + message1);
        String[] parts = message1.split(",");
        String clientID = parts[0];
        String nonceA = parts[1];

        System.out.println(" ------------------");

        // Step 2: Generate nonce NB and send back encrypted response
        String nonceB = Encryption.generateNonce();
        String response = "Bob," + nonceA;
        System.out.println(" Message 2: " + String.format("%s || E ( %s )",nonceB,response) );
        String encryptedResponse = Encryption.AESencrypt(response, SharedKey);
        out.println(nonceB + "," + encryptedResponse);
        System.out.println(" Sent Message 2: " + nonceB + "," + encryptedResponse);

        System.out.println(" ------------------");

        // Step 3: Receive encrypted message from client
        String message3 = in.readLine();
        System.out.println(" Received Message 3: " + message3);
        String decryptedMessage3 = Encryption.AESdecrypt(message3, SharedKey);
        System.out.println(" Decrypted Message 3: " + decryptedMessage3);
        System.out.println("--------------------");

        // GENERATE MASTER SECRET
        MasterSecret = Encryption.generateSecretKey("AES");
        out.println(Encryption.encodeKey(MasterSecret));
        System.out.printf("Master Key Generated: %s%n",Encryption.encodeKey(MasterSecret));

        // Derive encryption and MAC keys from the Master Secret (Part 3)
        encryptionKey = Encryption.deriveKey(MasterSecret, "ENCRYPT");
        macKey = Encryption.deriveKey(MasterSecret, "MAC");

        System.out.println("Derived Encryption Key: " + Encryption.encodeKey(encryptionKey));
        System.out.println("Derived MAC Key: " + Encryption.encodeKey(macKey));
    }

    // part 4
    private void logTransaction(String username, String action) {
        System.out.printf("LOG: %s | %s | %s%n", username, action, new Date());
        writeEncryptedAuditLog(username, action); // part 4
    }

    // write audit log entry to encrypted file
    private void writeEncryptedAuditLog(String username, String action) {
        try {
            String timestamp = new Date().toString();
            String rawLog = username + " | " + action + " | " + timestamp;

            String encryptedLog = Encryption.AESencrypt(rawLog, encryptionKey);

            FileWriter fw = new FileWriter("audit.log", true); // append mode
            fw.write(encryptedLog + "\n");
            fw.close();

        } catch (Exception e) {
            System.out.println("Error writing to audit log: " + e.getMessage());
        }
    }
    // part 4 - export decrypted audit log to a file only
    private void exportDecryptedAuditLog() {
        try {
            BufferedReader reader = new BufferedReader(new FileReader("audit.log"));
            FileWriter writer = new FileWriter("decrypted_audit.log");

            String line;
            while ((line = reader.readLine()) != null) {
                try {
                    String decrypted = Encryption.AESdecrypt(line, encryptionKey);
                    writer.write(decrypted + "\n");
                } catch (Exception ignored) {
                    // skip invalid lines silently
                }
            }

            reader.close();
            writer.close();
            System.out.println("Decrypted log saved to 'decrypted_audit.log'");
        } catch (IOException e) {
            System.out.println("Failed to export audit log: " + e.getMessage());
        }
    }
    //replay protection
    private boolean isReplay(String timestampStr, String nonce) {
        try {
            long currentTime = System.currentTimeMillis();
            long messageTime = Long.parseLong(timestampStr);
            long timeDiff = Math.abs(currentTime - messageTime);

            if (timeDiff > MAX_TIME_DIFF_MS) {
                System.out.println("Rejected: Message too old or time-skewed.");
                return true;
            }

            synchronized (usedNonces) {
                if (usedNonces.contains(nonce)) {
                    System.out.println("Rejected: Nonce reused.");
                    return true;
                }
                usedNonces.add(nonce);
            }

            // Add this line for confirmation
            System.out.println("Timestamp and nonce validated.");
            return false;
        } catch (Exception e) {
            System.out.println("Timestamp or nonce validation failed: " + e.getMessage());
            return true;
        }
    }

}
