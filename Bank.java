import sun.security.krb5.EncryptedData;

import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import java.io.IOException;
import java.security.PrivateKey;
import java.util.logging.Logger;

public class Bank {
    private final int port;

    private static final Logger logger = Logger.getLogger(Bank.class.getName());

    public Bank(int port) {
        this.port = port;
        PrivateKey privateKey = null;
    }

    public static void main(String[] args) {
        Bank bank = new Bank(1234);
        bank.run();
    }

    public static EncryptedData getSymmetricKey() {
        return null;
    }

    public static EncryptedData getPrivateKey() {
        return null;
    }



    public void run() {
        try {
            SSLServerSocketFactory sslServerSocketFactory = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();
            SSLServerSocket sslServerSocket = (SSLServerSocket) sslServerSocketFactory.createServerSocket(port);
            logger.info("Bank server started");
            while (true) {
                SSLSocket sslSocket = (SSLSocket) sslServerSocket.accept();
                logger.info("Connected to ATM");
                new Thread(new BankThread(sslSocket)).start();
            }
        } catch (IOException e) {
            logger.severe("Failed to start bank server");
            e.getMessage();
        }
    }



}
