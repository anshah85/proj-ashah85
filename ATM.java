import java.util.logging.Logger;

public class ATM {
    private String bankServer;
    private int bankPort;

    public static final Logger logger = Logger.getLogger(ATM.class.getName());

    public ATM(String bankServer, int bankPort) {
        this.bankServer = bankServer;
        this.bankPort = bankPort;
    }

    public void run() {
//        prompt the user to enter their ID and password
    }

    public static void main(String[] args) {
        ATM atm = new ATM("localhost", 1234);
        atm.run();

    }
}
