package com.Mailbox;

import java.util.Date;

public class Logging {
    
    private static final Boolean LOGGING_ENABLED = false;
    
    public static void printLog(String category, String logText) {
        if (LOGGING_ENABLED) {
            long time = (new Date()).getTime();
            System.out.println("[" + time + "] [" + category + "] " + logText);
        }
    }
    
    public static void printError(String logText) {
        if (LOGGING_ENABLED) {
            printLog("ERR", "! " + logText);
        }
    }
    
}
