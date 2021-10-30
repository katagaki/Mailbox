package com.Mailbox;

import com.Mailbox.Logging;

public class Shared {
    
    public static int getPort(String argumentSpecified) {
        
        int port;
        
        if (argumentSpecified != null || argumentSpecified != "") {
            port = Integer.parseInt(argumentSpecified);
            if (port > 65355 || port <= 0) {
                Logging.printError("Invalid port number specified. Port number should be between 1 and 65535.");
                port = 39443;
            }
        } else {
            port = 39443;
        }
        
        return port;
        
    }
    
}
