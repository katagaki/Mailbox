# Mailbox
## Encrypted communication between client and server

**CAUTION: This code is provided AS-IS and should be considered an archive for reference purposes only. The code may contain errors or bugs that may not be fixed.**

## Test environment

Mailbox was tested in the following environment:
* MacBook Pro (Intel)
* macOS 11.2 Beta (20D5042d)
* Java(TM) SE Runtime Environment (build 15.0.1+9-18)
* Java HotSpot(TM) 64-Bit Server VM (build 15.0.1+9-18, mixed mode, sharing)
* javac 15.0.1

## Compiling

Compilation should be performed from the root directory containing the src and bin folders.

### Server

    javac -d bin -sourcepath src src/com/Mailbox/Host.java

### Client

    javac -d bin -sourcepath src src/com/Mailbox/Client.java

## Preparing the host

### Create configuration file

The empty configuration file needs to be in the working directory on first start. A sample Config.cfg is already provided in the bin folder, with a large prime number and generator already set. The password for the sample Config.cfg is **hunter2** (without double stars if reading from a plain text viewer). 

To copy the configuration file template:

    cp Config.cfg bin/Config.cfg

## Starting host

The host should be started from within the bin directory.

### Syntax

    java com.Mailbox.Host <port>

### Examples

Start the Mailbox host on the default server port 39443, listening on the default client port 39444

    java com.Mailbox.Host

Start the Mailbox host on the default server port 8443, listening on the default client port 8480

    java com.Mailbox.Host 8443 8480

## Starting client

The client should be started from within the bin directory.

### Syntax

    java com.Mailbox.Client <hostname> <server-port> <client-port>

### Examples

Start the Mailbox client on the default port 39444 and connect to a server on the local machine with the default port 39443

    java com.Mailbox.Client

Start the Mailbox client on the port 8480 and connect to a server on the local machine with the port 8443

    java com.Mailbox.Client localhost 8443 8480

Start the Mailbox client on the port 12445 and connect to a remote server with the port 12443

    java com.Mailbox.Client 18.140.206.151 12443 12445

## Exiting host/client

To exit the conversation, type **exit** at any point in the conversation (without double stars if reading from a plain text viewer).

## Using CryptoTester

CryptoTester is included to test key generation in Mailbox.

### Compiling

Compilation should be performed from the directory containing the src and bin folders.

    javac -d bin -sourcepath src src/com/Mailbox/CryptoTester.java

### Running

CryptoTester should be started from within the bin directory.

    java com.Mailbox.CryptoTester

## Additional design considerations

* All communications are prefixed with a special message type to identify them. Depending on the step in the key exchange, this prefix may be included with the encrypted message.
* Encryption key size chosen is 2048-bit for all key generation.
* Encryption method chosen is AES cipher block chaining with PKCS#5 padding for all encryption/decryption.
* Encrypted messages are encoded with Base64 before being sent to the other party. The other party then decodes the Base64 message, and then decrypts the message.
* All logging can be turned on/off in the Logging class source code.
