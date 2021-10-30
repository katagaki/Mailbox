package com.Mailbox;

import com.Mailbox.Logging;

public class Networking {
    
    public static byte[] getByteArray(String message) {
        return message.getBytes();
    }
    
    public static String getMessage(MessageType messageType, String message) {
        // Data header is suffixed with 3 colons (:::)
        return messageType.getHeader() + ":::" + message;
    }
    
    public static byte[] getMessageByteArray(MessageType messageType, String message) {
        String completeMessage = getMessage(messageType, message);
        return getByteArray(completeMessage);
    }
    
    public static String getMessage(String message) {
        String[] messageParts = message.split(":::");
        if (messageParts.length <= 1) {
            return "";
        } else {
            String finalMessage = "";
            for (int i = 1; i < messageParts.length; i++) {
                finalMessage = finalMessage + (i == 1 ? "" : ":::") + messageParts[i];
            }
            return finalMessage;
        }
    }
    
    public static MessageType getMessageType(String message) {
        String[] messageParts = message.split(":::");
        try {
            MessageType messageType = MessageType.valueOf(messageParts[0]);
            return messageType;
        } catch (Exception e) {
            Logging.printError("Unknown message type received.");
            e.printStackTrace();
            return MessageType.MBCL_SYS_UNKN;
        }
    }
    
    public static MessageType getMessageType(byte[] messageByteArray) {
        String message = new String(messageByteArray);
        return getMessageType(message);
    }
    
    public enum MessageType {
        
        MBCL_MSG_USER("MBCL_MSG_USER"),
        MBCL_DHH_KYEX("MBCL_DHH_KYEX"),
        MBCL_CHL_NNCE("MBCL_CHL_NNCE"),
        MBCL_SES_OPEN("MBCL_SES_OPEN"),
        MBCL_SES_EXIT("MBCL_SES_EXIT"),
        MBCL_SYS_UNKN("MBCL_SYS_UNKN");
        
        // MBCL_MSG_TEST: Server test data
        // MBCL_MSG_USER: User message
        // MBCL_DHH_KYEX: Diffie Hellman key exchange
        // MBCL_PWD_AUTH: Password authentication
        // MBCL_CHL_NNCE: Nonce challenge request
        // MBCL_SES_OPEN: Open session
        // MBCL_SES_EXIT: End session
        
        private String header;
        
        MessageType(String header) {
            this.header = header;
        }
        
        public String getHeader() {
            return header;
        }
        
    }
    
}
