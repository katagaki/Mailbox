package com.Mailbox;

import com.Mailbox.Crypto;
import com.Mailbox.Networking;
import com.Mailbox.Networking.MessageType;
import com.Mailbox.Shared;
import java.math.BigInteger;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.util.Scanner;

// Mailbox client
// Default port: 39444

public class Client {
    
    private static int hostPort = 39443;
    private static int clientPort = 39444;
    private static InetAddress hostAddress = null;
    
    private static BigInteger generator = BigInteger.ZERO;
    private static BigInteger sharedPrime = BigInteger.ZERO;
    private static BigInteger privateKey = BigInteger.ZERO;
    private static BigInteger publicKey = BigInteger.ZERO;
    private static BigInteger sharedSecret = BigInteger.ZERO;
    
    private static BigInteger hostPublicKey = BigInteger.ZERO;
    
    public static void main(String[] args) throws Exception {
        
        // Get password from user
        
        String passwordHash = "";
        Scanner scanner = new Scanner(System.in);
        
        System.out.print("The client requires a password to begin. Enter your password: ");
        passwordHash = Crypto.getSHA1(scanner.nextLine());
        
        if (args.length == 3) {
            hostAddress = InetAddress.getByName(args[0]);
            hostPort = Shared.getPort(args[1]);
            clientPort = Shared.getPort(args[2]);
        } else {
            hostAddress = InetAddress.getByName("localhost");
        }
        
        Logging.printLog("MSG", "Client started (port " + clientPort + ").");
        System.out.println("Client started.");
        
        DatagramSocket socket = new DatagramSocket(clientPort);
        
        Logging.printLog("MSG", "Connecting to host...");
        
        // Open a new session with host
        
        byte[] sessionOpenMessageByteArray = Networking.getMessageByteArray(MessageType.MBCL_SES_OPEN, "Bob");
        DatagramPacket sessionOpenRequestPacket = new DatagramPacket(sessionOpenMessageByteArray, sessionOpenMessageByteArray.length, hostAddress, hostPort);
        
        send(socket, sessionOpenRequestPacket);
        
        // Get public key from the host
        
        byte[] sessionOpenConfirmationByteArray = new byte[1000000];
        DatagramPacket sessionOpenConfirmationPacket = new DatagramPacket(sessionOpenConfirmationByteArray, sessionOpenConfirmationByteArray.length);
        
        Logging.printLog("MSG", "Waiting for a session open confirmation...");
        
        receive(socket, sessionOpenConfirmationPacket);
        
        // Verify the public key from the host
        
        String sessionOpenConfirmationMessage = new String(sessionOpenConfirmationPacket.getData(), 0, sessionOpenConfirmationPacket.getLength());
        
        switch (Networking.getMessageType(sessionOpenConfirmationMessage)) {
            case MBCL_DHH_KYEX:
                Logging.printLog("MSG", "Session open confirmation received.");
                break;
            case MBCL_SES_EXIT:
                triggerCloseSession(Networking.getMessage(sessionOpenConfirmationMessage));
                break;
            default:
                Logging.printError("Message received from host, but it was not a session open confirmation.");
                closeSession(socket, "Session not opened correctly.");
                break;
        }
        
        // Decrypt the request to check the validity of the password
        
        String encryptedSessionOpenConfirmationRequest = Networking.getMessage(new String(sessionOpenConfirmationPacket.getData(), 0, sessionOpenConfirmationPacket.getLength()));
        String decryptedSessionOpenConfirmationRequest = Crypto.decrypt(encryptedSessionOpenConfirmationRequest, passwordHash);
        
        if (decryptedSessionOpenConfirmationRequest == null) {
            Logging.printError("Could not decrypt the session open confirmation due to an incorrect password.");
            closeSession(socket, "User entered the wrong password.");
        }
        
        // Get the decrypted values from the host
        
        String[] decryptedValues = decryptedSessionOpenConfirmationRequest.split(":::");
        sharedPrime = new BigInteger(decryptedValues[0]);
        generator = new BigInteger(decryptedValues[1]);
        hostPublicKey = new BigInteger(decryptedValues[2]);
        
        // Generate a new public private key pair
        
        privateKey = Crypto.getPrime(2048);
        publicKey = Crypto.getPublicKey(privateKey, generator, sharedPrime);
        
        // Get the shared secret
        
        BigInteger sharedSecret = Crypto.getSharedSecret(hostPublicKey, privateKey, sharedPrime);
        
        // Send the public key to the host
        
        byte[] publicKeyMessage = Networking.getByteArray(Crypto.encrypt(Networking.getMessage(MessageType.MBCL_DHH_KYEX, publicKey.toString()), passwordHash));
        DatagramPacket publicKeyMessagePacket = new DatagramPacket(publicKeyMessage, publicKeyMessage.length, hostAddress, hostPort);
        
        Logging.printLog("MSG", "Sending the public key to the host...");
        
        send(socket, publicKeyMessagePacket);
        
        // Wait for host nonce challenge request
        
        byte[] hostNonceChallengeRequestByteArray = new byte[1000000];
        DatagramPacket hostNonceChallengeRequestPacket = new DatagramPacket(hostNonceChallengeRequestByteArray, hostNonceChallengeRequestByteArray.length);
        
        Logging.printLog("MSG", "Waiting for a host nonce challenge request...");
        
        receive(socket, hostNonceChallengeRequestPacket);
        
        // Decrypt the host nonce challenge request
        
        String encryptedHostNonceChallengeRequestMessage = new String(hostNonceChallengeRequestPacket.getData(), 0, hostNonceChallengeRequestPacket.getLength());
        String decryptedHostNonceChallengeRequestMessage = Crypto.decrypt(encryptedHostNonceChallengeRequestMessage, sharedSecret);
        
        if (decryptedHostNonceChallengeRequestMessage == null) {
            Logging.printError("Could not decrypt the host nonce challenge request.");
            closeSession(socket, "Did not correctly receive host nonce challenge request.");
        }
        
        // Verify the host nonce challenge request
        
        switch (Networking.getMessageType(decryptedHostNonceChallengeRequestMessage)) {
            case MBCL_CHL_NNCE:
                Logging.printLog("MSG", "Host nonce challenge request received.");
                break;
            case MBCL_SES_EXIT:
                triggerCloseSession(Networking.getMessage(decryptedHostNonceChallengeRequestMessage));
                break;
            default:
                Logging.printError("Message received from host, but it was not a nonce challenge request.");
                closeSession(socket, "Did not correctly receive host nonce challenge request.");
                break;
        }
        
        // Process host nonce challenge request
        
        long hostNonce = Long.parseLong(Networking.getMessage(decryptedHostNonceChallengeRequestMessage));
        long clientNonce = Crypto.getNonce();
        
        hostNonce = hostNonce + 1;
        
        // Send the challenge response and client nonce challenge request
        
        byte[] hostNonceResponseMessage = Networking.getByteArray(Crypto.encrypt(Networking.getMessage(MessageType.MBCL_CHL_NNCE, String.valueOf(hostNonce) + ":::" + String.valueOf(clientNonce)), sharedSecret));
        DatagramPacket hostNonceResponseMessagePacket = new DatagramPacket(hostNonceResponseMessage, hostNonceResponseMessage.length, hostAddress, hostPort);
        
        Logging.printLog("MSG", "Sending the nonce challenge response with the client nonce challenge request to the host...");
        
        send(socket, hostNonceResponseMessagePacket);
        
        // Get client nonce challenge response
        
        byte[] clientNonceResponseByteArray = new byte[1000000];
        DatagramPacket clientNonceResponsePacket = new DatagramPacket(clientNonceResponseByteArray, clientNonceResponseByteArray.length);
        
        Logging.printLog("MSG", "Waiting for the client nonce challenge response...");
        
        receive(socket, clientNonceResponsePacket);
        
        // Decrypt the client nonce challenge response
        
        String encryptedClientNonceResponseMessage = new String(clientNonceResponsePacket.getData(), 0, clientNonceResponsePacket.getLength());
        String decryptedClientNonceResponseMessage = Crypto.decrypt(encryptedClientNonceResponseMessage, sharedSecret);
        
        if (decryptedClientNonceResponseMessage == null) {
            Logging.printError("Could not decrypt the host nonce challenge response.");
            closeSession(socket, "Did not correctly receive host nonce challenge response.");
        }
        
        // Verify the client nonce challenge response
        
        switch (Networking.getMessageType(decryptedClientNonceResponseMessage)) {
            case MBCL_CHL_NNCE:
                Logging.printLog("MSG", "Client nonce challenge response received.");
                break;
            case MBCL_SES_EXIT:
                triggerCloseSession("Networking.getMessage(decryptedClientNonceResponseMessage)");
                break;
            default:
                Logging.printError("Message received from host, but it was not a nonce challenge message.");
                closeSession(socket, "Did not correctly receive host nonce challenge response.");
                break;
        }
        
        String[] clientNonceResponses = Networking.getMessage(decryptedClientNonceResponseMessage).split(":::");
        long clientNonceResponse = Long.parseLong(clientNonceResponses[0]);
        
        if (clientNonceResponse - 1 == clientNonce) {
            Logging.printLog("MSG", "Client nonce challenge successful.");
        } else {
            Logging.printError("Client nonce challenge failed.");
            closeSession(socket, "Client nonce challenge failed.");
        }
        
        // Begin conversation with host
        
        Logging.printLog("MSG", "Conversation with host began.");
        System.out.println("Private conversation began with a verified host. Type your message and press Return to send your message.");
        
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
                                    DatagramPacket messagePacket = new DatagramPacket(messageBuffer, messageBuffer.length, hostAddress, hostPort);
                                    
                                    Logging.printLog("MSG", "Sending exit signal to host...");
                                    send(socket, messagePacket);
                                    
                                    triggerCloseSession("Session closed by user.");
                                    
                                } else {
                                    
                                    String decryptedMessageHash = Crypto.getSHA1(sharedSecret.toString() + decryptedMessage + sharedSecret.toString());
                                    String encryptedMessage = Crypto.encrypt(Networking.getMessage(MessageType.MBCL_MSG_USER, decryptedMessage + ":::" + decryptedMessageHash), sharedSecret);
                                    messageBuffer = encryptedMessage.getBytes();
                                    DatagramPacket messagePacket = new DatagramPacket(messageBuffer, messageBuffer.length, hostAddress, hostPort);
                                    
                                    Logging.printLog("MSG", "Sending message to host...");
                                    send(socket, messagePacket);
                                    
                                }
                            }
                            
                        }
                    }
                } catch (Exception e) {
                    Logging.printError("Failed to send message to host.");
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
                                    triggerCloseSession("Session closed by host.");
                                    break;
                                case MBCL_MSG_USER:
                                    String[] splitMessage = Networking.getMessage(decryptedMessage).split(":::");
                                    String receivedMessage = splitMessage[0];
                                    String receivedHash = splitMessage[1];
                                    if (receivedHash.startsWith(Crypto.getSHA1(sharedSecret.toString() + receivedMessage + sharedSecret.toString()))) {
                                        System.out.println("Host: " + receivedMessage);
                                    } else {
                                        Logging.printError("Message received from host, but the hash did not match.");
                                    }
                                    break;
                                default:
                                    Logging.printError("Message received from host, but it was not a part of the conversation.");
                                    closeSession(socket, "Session was interrupted or intercepted.");
                                    break;
                            }
                            
                        }
                    }
                } catch (Exception e) {
                    Logging.printError("Failed to receive a message from the host.");
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
        DatagramPacket sessionCloseRequestPacket = new DatagramPacket(sessionCloseMessage, sessionCloseMessage.length, hostAddress, hostPort);
        send(socket, sessionCloseRequestPacket);
        System.exit(1);
    }
    
}
