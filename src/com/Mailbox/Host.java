package com.Mailbox;

import com.Mailbox.Crypto;
import com.Mailbox.Networking;
import com.Mailbox.Networking.MessageType;
import com.Mailbox.Logging;
import com.Mailbox.Shared;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.lang.Runnable;
import java.lang.Thread;
import java.math.BigInteger;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Scanner;

// Mailbox host:
// Default port: 39443

public class Host {
    
    private static int hostPort = 39443;
    private static int clientPort = 39444;
    private static InetAddress clientAddress = null;
    
    private static BigInteger generator = BigInteger.ZERO;
    private static BigInteger sharedPrime = BigInteger.ZERO;
    private static BigInteger privateKey = BigInteger.ZERO;
    private static BigInteger publicKey = BigInteger.ZERO;
    private static BigInteger sharedSecret = BigInteger.ZERO;
    
    private static BigInteger clientPublicKey = BigInteger.ZERO;
    
    public static void main(String[] args) throws Exception {
        
        if (args.length == 2) {
            hostPort = Shared.getPort(args[0]);
            clientPort = Shared.getPort(args[1]);
        }
        
        Logging.printLog("MSG", "Host started (port " + hostPort + ").");
        System.out.println("Host started.");
        
        // Check configuration for initial setup
        
        Path workingPath = Paths.get(".");
        Path configPath = Paths.get(workingPath.toAbsolutePath().normalize().toString() + "/Config.cfg");
        Charset charset = StandardCharsets.UTF_8;
        String passwordHash = "";
        Scanner scanner = new Scanner(System.in);
        Boolean configChanged = false;
        
        try {
            
            Logging.printLog("MSG", "Reading existing configuration file...");
            
            // Read the existing configuration
            List<String> configLines = Files.readAllLines(configPath, charset);
            for (String configLine: configLines) {
                switch (configLine.split("=")[0]) {
                    case "pwdhash":
                        if (configLine.split("=").length >= 2) {
                            passwordHash = configLine.split("=")[1];
                        }
                        
                        if (passwordHash == "") {
                            
                            // Prompt the user to set a new password if the password is empty
                            System.out.print("Enter a new password for the host: ");
                            passwordHash = Crypto.getSHA1(scanner.nextLine());
                            configChanged = true;
                            
                            Logging.printLog("MSG", "New password pending commit to configuration file.");
                            
                        }
                        break;
                        
                    case "prime":
                        if (configLine.split("=").length >= 2) {
                            sharedPrime = new BigInteger(configLine.split("=")[1]);
                        }
                        
                        if (sharedPrime == BigInteger.ZERO) {
                            
                            // Generate a new 2048-bit prime if the prime was not set
                            sharedPrime = Crypto.getPrime(2048);
                            configChanged = true;
                            
                            Logging.printLog("MSG", "New large prime number pending commit to configuration file.");
                            
                        }
                        break;
                        
                    case "generator":
                        if (configLine.split("=").length >= 2) {
                            generator = new BigInteger(configLine.split("=")[1]);
                        }
                        
                        if (generator == BigInteger.ZERO) {
                            
                            // Set generator value
                            generator = Crypto.getPrime(2);
                            configChanged = true;
                            
                            Logging.printLog("MSG", "New generator value pending commit to configuration file.");
                            
                        }
                        break;
                        
                    default: break;
                }
            }
            
            // Update the configuration file if the configuration changed
            if (configChanged) {
                
                Logging.printLog("MSG", "Writing new configuration file...");
                
                String configString = "pwdhash=" + passwordHash + "\n" +
                                      "prime=" + sharedPrime + "\n" +
                                      "generator=" + generator;
                FileWriter configWriter = new FileWriter(new File(configPath.toAbsolutePath().normalize().toString()), false);
                configWriter.write(configString);
                configWriter.close();
                
                Logging.printLog("MSG", "New configuration file successfully written to disk.");
                
            }
            
        } catch (Exception e) {
            Logging.printError("Failed to load the configuration file. Check that the configuration file is in the correct format.");
            e.printStackTrace();
            System.exit(1);
        }
        
        DatagramSocket socket = new DatagramSocket(hostPort);
        
        // Generate a new public private key pair
        
        privateKey = Crypto.getPrime(2048);
        publicKey = Crypto.getPublicKey(privateKey, generator, sharedPrime);
        
        // Wait for client to open a new session
        
        byte[] sessionOpenByteArray = new byte[1000000];
        DatagramPacket sessionOpenPacket = new DatagramPacket(sessionOpenByteArray, sessionOpenByteArray.length);
        
        Logging.printLog("MSG", "Waiting for client...");
        
        receive(socket, sessionOpenPacket);
        
        String sessionOpenMessage = new String(sessionOpenPacket.getData(), 0, sessionOpenPacket.getLength());
        
        if (Networking.getMessageType(sessionOpenMessage) == MessageType.MBCL_SES_OPEN) {
            if (Networking.getMessage(sessionOpenMessage).startsWith("Bob")) {
                Logging.printLog("MSG", "Session open request received.");
                clientAddress = sessionOpenPacket.getAddress();
            } else {
                Logging.printError("Session open request received from client, but the session open request message was incorrect.");
            }
        } else {
            Logging.printError("Message received from client, but it was not a session open request.");
        }
        
        // Send the public key to the client
        
        byte[] sessionStartMessage = Networking.getMessageByteArray(MessageType.MBCL_DHH_KYEX, Crypto.encrypt(sharedPrime.toString() + ":::" + generator.toString() + ":::" + publicKey.toString(), passwordHash));
        DatagramPacket sessionOpenRequestPacket = new DatagramPacket(sessionStartMessage, sessionStartMessage.length, clientAddress, clientPort);
        
        Logging.printLog("MSG", "Sending a session open confirmation containing the shared prime, generator, and public key...");
        
        send(socket, sessionOpenRequestPacket);
        
        // Get the public key from client
        
        byte[] clientPublicKeyByteArray = new byte[1000000];
        DatagramPacket clientPublicKeyPacket = new DatagramPacket(clientPublicKeyByteArray, clientPublicKeyByteArray.length);
        
        Logging.printLog("MSG", "Waiting for the client's public key...");
        
        receive(socket, clientPublicKeyPacket);
        
        // Decrypt received values
        
        String encryptedClientPublicKeyMessage = new String(clientPublicKeyPacket.getData(), 0, clientPublicKeyPacket.getLength());
        String decryptedClientPublicKeyMessage = Crypto.decrypt(encryptedClientPublicKeyMessage, passwordHash);
        
        if (decryptedClientPublicKeyMessage == null) {
            Logging.printError("Could not decrypt the client public key due to an incorrect password.");
            closeSession(socket, "Did not correctly receive public key due to an incorrect password.");
        }
        
        // Calculate shared secret
        
        switch (Networking.getMessageType(decryptedClientPublicKeyMessage)) {
            case MBCL_DHH_KYEX:
                Logging.printLog("MSG", "Client public key received.");
                break;
            case MBCL_SES_EXIT:
                triggerCloseSession(Networking.getMessage(decryptedClientPublicKeyMessage));
                break;
            default:
                Logging.printError("Message received from client, but it was not a key exchange message.");
                closeSession(socket, "Did not correctly receive public key.");
                break;
        }
        
        BigInteger clientPublicKey = new BigInteger(Networking.getMessage(decryptedClientPublicKeyMessage));
        BigInteger sharedSecret = Crypto.getSharedSecret(clientPublicKey, privateKey, sharedPrime);
        
        // Send host nonce challenge request
        
        long hostNonce = Crypto.getNonce();
        byte[] hostNonceChallengeRequestMessage = Networking.getByteArray(Crypto.encrypt(Networking.getMessage(MessageType.MBCL_CHL_NNCE, String.valueOf(hostNonce)), sharedSecret));
        DatagramPacket hostNonceChallengeRequestPacket = new DatagramPacket(hostNonceChallengeRequestMessage, hostNonceChallengeRequestMessage.length, clientAddress, clientPort);
        
        Logging.printLog("MSG", "Sending a host nonce challenge request...");
        
        send(socket, hostNonceChallengeRequestPacket);
        
        // Wait for host nonce challenge response
        
        byte[] hostNonceResponseByteArray = new byte[1000000];
        DatagramPacket hostNonceResponsePacket = new DatagramPacket(hostNonceResponseByteArray, hostNonceResponseByteArray.length);
        
        Logging.printLog("MSG", "Waiting for the host nonce challenge response...");
        
        receive(socket, hostNonceResponsePacket);
        
        // Decrypt the host nonce challenge response
        
        String encryptedHostNonceResponseMessage = new String(hostNonceResponsePacket.getData(), 0, hostNonceResponsePacket.getLength());
        String decryptedHostNonceResponseMessage = Crypto.decrypt(encryptedHostNonceResponseMessage, sharedSecret);
        
        if (decryptedHostNonceResponseMessage == null) {
            Logging.printError("Could not decrypt the host nonce challenge response.");
            closeSession(socket, "Did not correctly receive host nonce challenge response.");
        }
        
        // Verify the host nonce challenge response
        
        switch (Networking.getMessageType(decryptedHostNonceResponseMessage)) {
            case MBCL_CHL_NNCE:
                Logging.printLog("MSG", "Host nonce challenge response received with a client nonce challenge request.");
                break;
            case MBCL_SES_EXIT:
                triggerCloseSession(Networking.getMessage(decryptedHostNonceResponseMessage));
                break;
            default:
                Logging.printError("Message received from client, but it was not a nonce challenge message.");
                closeSession(socket, "Did not correctly receive host nonce challenge response.");
                break;
        }
        
        String[] hostNonceResponses = Networking.getMessage(decryptedHostNonceResponseMessage).split(":::");
        long hostNonceResponse = Long.parseLong(hostNonceResponses[0]);
        long clientNonce = Long.parseLong(hostNonceResponses[1]);
        
        Logging.printLog("MSG", "Creating client nonce challenge response...");
        
        clientNonce = clientNonce + 1;
        
        if (hostNonceResponse - 1 == hostNonce) {
            Logging.printLog("MSG", "Host nonce challenge successful.");
        } else {
            Logging.printError("Host nonce challenge failed.");
            closeSession(socket, "Host nonce challenge failed.");
        }
        
        // Send the client nonce challenge response
        
        byte[] clientNonceResponseMessage = Networking.getByteArray(Crypto.encrypt(Networking.getMessage(MessageType.MBCL_CHL_NNCE, String.valueOf(clientNonce)), sharedSecret));
        DatagramPacket clientNonceResponseMessagePacket = new DatagramPacket(clientNonceResponseMessage, clientNonceResponseMessage.length, clientAddress, clientPort);
        
        Logging.printLog("MSG", "Sending the client nonce challenge response to the client...");
        
        send(socket, clientNonceResponseMessagePacket);
        
        // Begin conversation with client
        
        Logging.printLog("MSG", "Conversation with client began.");
        System.out.println("Private conversation began with a verified client. Type your message and press Return to send your message.");
        
        // Create 2 threads so that we can be listening and also sending at the same time
        Thread sendThread;
        Thread receiveThread;
        
        sendThread = new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    while (true) {
                        synchronized(this) {
                            
                            byte[] messageBuffer = new byte[1000000];
                            
                            String decryptedMessage = scanner.nextLine();
                            
                            if (decryptedMessage.contains(":::")) {
                                Logging.printError("Message cotains reserved characters and will not be sent.");
                            } else {
                                if (decryptedMessage.toLowerCase().startsWith("exit")) {
                                    
                                    String encryptedMessage = Crypto.encrypt(Networking.getMessage(MessageType.MBCL_SES_EXIT, ""), sharedSecret);
                                    messageBuffer = encryptedMessage.getBytes();
                                    DatagramPacket messagePacket = new DatagramPacket(messageBuffer, messageBuffer.length, clientAddress, clientPort);
                                    
                                    Logging.printLog("MSG", "Sending exit signal to client...");
                                    send(socket, messagePacket);
                                    
                                    triggerCloseSession("Session closed by user.");
                                    
                                } else {
                                    
                                    String decryptedMessageHash = Crypto.getSHA1(sharedSecret.toString() + decryptedMessage + sharedSecret.toString());
                                    String encryptedMessage = Crypto.encrypt(Networking.getMessage(MessageType.MBCL_MSG_USER, decryptedMessage + ":::" + decryptedMessageHash), sharedSecret);
                                    messageBuffer = encryptedMessage.getBytes();
                                    DatagramPacket messagePacket = new DatagramPacket(messageBuffer, messageBuffer.length, clientAddress, clientPort);
                                    
                                    Logging.printLog("MSG", "Sending message to client...");
                                    send(socket, messagePacket);
                                    
                                }
                            }
                                                        
                        }
                    }
                } catch (Exception e) {
                    Logging.printError("Failed to send message to client.");
                }
            }
        });
        
        receiveThread = new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    while (true) {
                        synchronized(this) {
                            
                            byte[] messageBuffer = new byte[1000000];
                            
                            DatagramPacket messagePacket = new DatagramPacket(messageBuffer, messageBuffer.length);
                            receive(socket, messagePacket);
                            
                            String encryptedMessage = new String(messagePacket.getData(), 0, messagePacket.getLength());
                            String decryptedMessage = Crypto.decrypt(encryptedMessage, sharedSecret);
                            
                            switch (Networking.getMessageType(decryptedMessage)) {
                                case MBCL_SES_EXIT:
                                    triggerCloseSession("Session closed by client.");
                                    break;
                                case MBCL_MSG_USER:
                                    String[] splitMessage = Networking.getMessage(decryptedMessage).split(":::");
                                    String receivedMessage = splitMessage[0];
                                    String receivedHash = splitMessage[1];
                                    if (receivedHash.startsWith(Crypto.getSHA1(sharedSecret.toString() + receivedMessage + sharedSecret.toString()))) {
                                        System.out.println("Client: " + receivedMessage);
                                    } else {
                                        Logging.printError("Message received from client, but the hash did not match.");
                                    }
                                    break;
                                default:
                                    Logging.printError("Message received from client, but it was not a part of the conversation.");
                                    closeSession(socket, "Session was interrupted or intercepted.");
                                    break;
                            }
                            
                        }
                    }
                } catch (Exception e) {
                    Logging.printError("Failed to receive a message from the client.");
                }
            }
        });
        
        // Begin running asynchronous threads
        
        sendThread.start();
        receiveThread.start();
        
        sendThread.join();
        receiveThread.join();
        
    }
    
    private static void receive(DatagramSocket socket, DatagramPacket packet) throws Exception {
        //Logging.printLog("NET", "Socket started listening for data.");
        socket.receive(packet);
        //Logging.printLog("NET", "Socket finished receiving data with the length " + packet.getLength() + ".");
    }
    
    private static void send(DatagramSocket socket, DatagramPacket packet) throws Exception {
        //Logging.printLog("NET", "Socket started sending data.");
        socket.send(packet);
        //Logging.printLog("NET", "Socket finished sending data with the length " + packet.getLength() + ".");
    }
    
    private static void triggerCloseSession(String reason) {
        Logging.printLog("MSG", "Session closed with the message: " + reason);
        System.exit(1);
    }
    
    private static void closeSession(DatagramSocket socket, String reason) throws Exception {
        byte[] sessionCloseMessage = Networking.getMessageByteArray(MessageType.MBCL_SES_EXIT, reason);
        Logging.printLog("MSG", "Sending a session close request...");
        DatagramPacket sessionCloseRequestPacket = new DatagramPacket(sessionCloseMessage, sessionCloseMessage.length, clientAddress, clientPort);
        send(socket, sessionCloseRequestPacket);
        System.exit(1);
    }
    
}
