import javax.net.ssl.SSLSocket;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.util.logging.Logger;

public class BankThread implements Runnable {

    private final SSLSocket sslSocket;

    private static final Logger logger = Logger.getLogger(BankThread.class.getName());

    public BankThread(SSLSocket sslSocket) {
        this.sslSocket = sslSocket;
    }

    @Override
    public void run() {
//        read encrypted symmetric key string from the socket
        logger.info("Received encrypted symmetric key string");
        try {
            DataInputStream dataInputStream = new DataInputStream(sslSocket.getInputStream());
            DataOutputStream dataOutputStream = new DataOutputStream(sslSocket.getOutputStream());

            String encryptedSymmetricKeyString = dataInputStream.readUTF();
            logger.info("Encrypted symmetric key string: " + encryptedSymmetricKeyString);
//            decrypt symmetric key string with private key
            assert Bank.getPrivateKey() != null;
            String symmetricKeyString = Bank.getPrivateKey().decrypt(encryptedSymmetricKeyString);
            logger.info("Symmetric key string: " + symmetricKeyString);
//            read encrypted ID and password from the socket
            String encryptedId = dataInputStream.readUTF();
            String encryptedPassword = dataInputStream.readUTF();
            logger.info("Encrypted ID: " + encryptedId);
            logger.info("Encrypted password: " + encryptedPassword);
//            decrypt ID and password with symmetric key
            assert Bank.getSymmetricKey() != null;
            String id = Bank.getSymmetricKey().decrypt(encryptedId);
            String password = Bank.getSymmetricKey().decrypt(encryptedPassword);
            logger.info("ID: " + id);
            logger.info("Password: " + password);
        } catch (Exception e) {
            logger.severe("Failed to read encrypted symmetric key string from socket");
            e.getMessage();
        }

    }

    public static void main(String[] args) {
        BankThread bankThread = new BankThread(null);
        bankThread.run();
    }

}
