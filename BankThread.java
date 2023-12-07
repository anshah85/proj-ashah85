import javax.net.ssl.SSLSocket;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.logging.Logger;

public class BankThread implements Runnable {

    private final SSLSocket sslSocket;
    private final PrivateKey privateKey;
    private final PublicKey publicKey;

    private static final Logger logger = Logger.getLogger(BankThread.class.getName());

    public BankThread(SSLSocket sslSocket, PrivateKey privateKey, PublicKey publicKey) {
        this.sslSocket = sslSocket;
        this.privateKey = privateKey;
        this.publicKey = publicKey;
    }

    @Override
    public void run() {
        try {
            DataInputStream dataInputStream = new DataInputStream(sslSocket.getInputStream());
            DataOutputStream dataOutputStream = new DataOutputStream(sslSocket.getOutputStream());

//            send public key to ATM
            String publicKeyString = publicKey.toString();
            dataOutputStream.writeUTF(publicKeyString);
            dataOutputStream.flush();
            logger.info("Sent public key to ATM");
        } catch (Exception e) {
            logger.severe("Failed to read encrypted symmetric key string from socket");
            e.printStackTrace();
        }

    }

    public static void main(String[] args) {
        BankThread bankThread = new BankThread(null, null, null);
        bankThread.run();
    }

}
