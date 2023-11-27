import javax.net.ssl.SSLSocket;
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

    }

    public static void main(String[] args) {
        BankThread bankThread = new BankThread(null);
        bankThread.run();
    }

}
