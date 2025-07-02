package coe817.project;


import javax.crypto.*;
import java.awt.*;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Scanner;

public class ATMClient {
    private static final SecretKey SharedKey = Encryption.convertToAESKey("fBhTxNXZ+fZbz2JOw8vqvtccdwjPShXUb0OF4E0wlWI=");
    private static User currentUser;
    private final static Scanner sc = new Scanner(System.in);
    private static SecretKey MasterSecret;

    private static BufferedReader in;
    private static PrintWriter out;
    private static Socket socket;

    // part 3
    private static SecretKey encryptionKey;
    private static SecretKey macKey;


    private static void register() throws Exception{
        /*USER REGISTRATION AND APPENDS TO ARRAY*/
        System.out.print("Enter Username: ");
        String username = sc.nextLine();
        System.out.print("Enter Password: ");
        String password = sc.nextLine();
//        System.out.println(username+" "+password);
        String command = String.format("register,%s,%s",username,password);
        out.println(Encryption.AESencrypt(command,SharedKey));
        System.out.println(in.readLine());
    }

    private static void login() throws Exception{
        /*LOGS IN USER, VERIFIES USER, SETS CURRENT USER TO LOGGED IN USER*/
        System.out.println("Enter Login Info: ");
        System.out.print("Username: ");
        String username = sc.nextLine();
        System.out.print("Password: ");
        String password = sc.nextLine();
        String command = String.format("login,%s,%s",username,password);
        out.println(Encryption.AESencrypt(command,SharedKey));
        String response = in.readLine();
        if(response.equals("LOGIN SUCCESSFUL")){
            currentUser = new User(username,password);
        }
        System.out.println(response);
    }

    public static void main(String[] args) {
        try {
            //Initial & Socket Info
            socket = new Socket("localhost", 4000);
            System.out.println("\n Client started on IP: " + InetAddress.getLocalHost().getHostAddress() + " Port: "
                    + socket.getLocalPort());
            System.out.println("\n Connected to Server IP: " + socket.getInetAddress().getHostAddress() + " Port: "
                    + socket.getPort());

            // Socket Reader and Writer
            in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            out = new PrintWriter(socket.getOutputStream(), true);

            // User Options:
            boolean isContinue = true;
            while(isContinue) {
                //LOGIN PHASE, ONLY UNTIL USER LOGINS
                if (currentUser == null) {
                    System.out.print("Options:\n1.Create User\n2.Login\n3.Exit\n::");
                    String option = sc.nextLine();
                    switch (option) {
                        case "1" -> {
                            // REGISTER
                            System.out.println();
                            register();
                        }
                        case "2" -> {
                            //LOGIN
                            System.out.println();
                            login();
                            if (currentUser != null){
                                authProtocol(in,out);
                            }

                        }
                        case "3" -> {
                            //EXIT
                            isContinue = false;
                        }
                        default -> System.out.println("Incorrect Option");
                    }
                    System.out.println();
                }else{ // AFTER LOGGED IN!!
                    System.out.print("Options:\n1.Deposit\n2.Withdraw\n3.Balance\n4.Logout\n::");
                    String option = sc.nextLine();
                    switch (option) {
                        // updated for part 4
                        case "1" -> {
                            System.out.print("Enter deposit amount: ");
                            String amount = sc.nextLine();

                            // Send command header encrypted with SharedKey
                            String timestamp = String.valueOf(System.currentTimeMillis());
                            String nonce = Encryption.generateNonce();

                            out.println(Encryption.AESencrypt("deposit", SharedKey));

                            // Build secure payload
                            String command = currentUser.getUsername() + ",deposit," + amount + "," + timestamp + "," + nonce;
                            String encrypted = Encryption.AESencrypt(command, encryptionKey);
                            String mac = Encryption.generateMAC(command, macKey);

                            // Send encrypted payload + MAC
                            out.println(encrypted + "," + mac);

                            // Receive and print server response
                            String responseLine = in.readLine();
                            System.out.println("Encrypted Server Response: " + responseLine);

                            String[] secureParts = responseLine.split(",", 2);
                            String encryptedResp = secureParts[0];
                            String respMAC = secureParts[1];

                            try {
                                String decryptedResp = Encryption.AESdecrypt(encryptedResp, encryptionKey);
                                if (Encryption.verifyMAC(decryptedResp, respMAC, macKey)) {
                                    System.out.println("Decrypted: " + decryptedResp);
                                } else {
                                    System.out.println("MAC verification failed. Response may have been tampered with.");
                                }
                            } catch (Exception e) {
                                System.out.println("ERROR: Failed to decrypt server response.");
                            }
                        }

                        case "2" -> {
                            System.out.print("Enter withdrawal amount: ");
                            String amount = sc.nextLine();

                            String timestamp = String.valueOf(System.currentTimeMillis());
                            String nonce = Encryption.generateNonce();

                            // Send command header
                            out.println(Encryption.AESencrypt("withdraw", SharedKey));

                            // Build secure payload
                            String command = currentUser.getUsername() + ",withdraw," + amount + "," + timestamp + "," + nonce;
                            String encrypted = Encryption.AESencrypt(command, encryptionKey);
                            String mac = Encryption.generateMAC(command, macKey);

                            out.println(encrypted + "," + mac);
                            String responseLine = in.readLine();
                            System.out.println("Encrypted Server Response: " + responseLine);

                            String[] secureParts = responseLine.split(",", 2);
                            String encryptedResp = secureParts[0];
                            String respMAC = secureParts[1];

                            try {
                                String decryptedResp = Encryption.AESdecrypt(encryptedResp, encryptionKey);
                                if (Encryption.verifyMAC(decryptedResp, respMAC, macKey)) {
                                    System.out.println("Decrypted: " + decryptedResp);
                                } else {
                                    System.out.println("MAC verification failed. Response may have been tampered with.");
                                }
                            } catch (Exception e) {
                                System.out.println("ERROR: Failed to decrypt server response.");
                            }
                        }

                        case "3" -> {
                            // Send command header
                            out.println(Encryption.AESencrypt("check_balance", SharedKey));
                            
                            String timestamp = String.valueOf(System.currentTimeMillis());
                            String nonce = Encryption.generateNonce();

                            // Build secure payload
                            String command = currentUser.getUsername() + ",check_balance," + timestamp + "," + nonce;
                            
                            String encrypted = Encryption.AESencrypt(command, encryptionKey);
                            String mac = Encryption.generateMAC(command, macKey);

                            out.println(encrypted + "," + mac);

                            String responseLine = in.readLine();
                            System.out.println("Encrypted Server Response: " + responseLine);

                            String[] secureParts = responseLine.split(",", 2);
                            String encryptedResp = secureParts[0];
                            String respMAC = secureParts[1];

                            try {
                                String decryptedResp = Encryption.AESdecrypt(encryptedResp, encryptionKey);
                                if (Encryption.verifyMAC(decryptedResp, respMAC, macKey)) {
                                    System.out.println("Decrypted: " + decryptedResp);
                                } else {
                                    System.out.println("MAC verification failed. Response may have been tampered with.");
                                }
                            } catch (Exception e) {
                                System.out.println("ERROR: Failed to decrypt server response.");
                            }
                        }

                        case "4" -> {
                            // Tell server to logout
                            out.println(Encryption.AESencrypt("logout", SharedKey));
                            currentUser = null;
                        }
                        default -> System.out.println("Incorrect Option");
                    }
                    System.out.println();
                }
            }

        }catch (Exception e){
            System.out.println("BackServer is OFFLINE");
            System.out.println(e);
        }
    }

    public static void authProtocol(BufferedReader in, PrintWriter out) throws Exception{
        // Step 1: Send identity and nonce NA to server
        String clientID = currentUser.getUsername();
        String nonceA = Encryption.generateNonce();
        out.println(clientID + "," + nonceA);
//        System.out.println("\n Sent Message 1: " + clientID + "," + nonceA);

//        System.out.println("\n ------------------");

        // Step 2: Receive response from server
        String response = in.readLine();
//        System.out.println("\n Received Message 2: " + response);
        String[] responseParts = response.split(",");
        String nonceB = responseParts[0];
        String encryptedMessage = responseParts[1];

        String decryptedMessage2 = Encryption.AESdecrypt(encryptedMessage, SharedKey);
//        System.out.println("\n Decrypted Message 2: " + decryptedMessage2);

//        System.out.println("\n ------------------");

        // Step 3: Send encrypted response
        String message3 = "Alice," + nonceB;
//        System.out.println("\n Message 3: " + String.format("E ( %s )",message3));
        String encryptedMessage3 = Encryption.AESencrypt(message3, SharedKey);
        out.println(encryptedMessage3);
//        System.out.println("\n Sent Message 3: " + encryptedMessage3);

        //Generate Master KEY
        MasterSecret = Encryption.convertToAESKey(in.readLine());
//        System.out.println(Encryption.encodeKey(MasterSecret));

        // Derive encryption and MAC keys from the Master Secret (Part 3)
        encryptionKey = Encryption.deriveKey(MasterSecret, "ENCRYPT");
        macKey = Encryption.deriveKey(MasterSecret, "MAC");

        System.out.println("Derived Encryption Key: " + Encryption.encodeKey(encryptionKey));
        System.out.println("Derived MAC Key: " + Encryption.encodeKey(macKey));
    }

}
