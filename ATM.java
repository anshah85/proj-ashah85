import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.Scanner;
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

        SSLSocketFactory sslSocketFactory = (SSLSocketFactory) SSLSocketFactory.getDefault();
        try (SSLSocket sslSocket = (SSLSocket) sslSocketFactory.createSocket(bankServer, bankPort)) {
            DataInputStream dataInputStream = new DataInputStream(sslSocket.getInputStream());
            DataOutputStream dataOutputStream = new DataOutputStream(sslSocket.getOutputStream());
            logger.info("Connected to bank server");
            Scanner scanner = new Scanner(System.in);
            boolean continueLoop = true;
            while (continueLoop) {
                System.out.println("Enter your ID: ");
                String id = scanner.nextLine();
                System.out.println("Enter your password: ");
                String password = scanner.nextLine();
//                ATM generates symmetric key
                SymmetricKey symmetricKey = new SymmetricKey();
                String symmetricKeyString = symmetricKey.getSymmetricKeyString();
//                ATM encrypts symmetric key string with bank's public key
//                String encryptedSymmetricKeyString = symmetricKey.encryptSymmetricKeyString(symmetricKeyString);
//                ATM encrypts ID and password with symmetric key
                String encryptedId = symmetricKey.encryptId(id);
                String encryptedPassword = symmetricKey.encryptPassword(password);

                logger.info("Symmetric key string: " + symmetricKeyString);

//                logger.info("Encrypted symmetric key string: " + encryptedSymmetricKeyString);
                logger.info("Encrypted ID: " + encryptedId);
                logger.info("Encrypted password: " + encryptedPassword);

//                dataOutputStream.writeUTF(encryptedSymmetricKeyString);
//                dataOutputStream.writeUTF(encryptedId);
//                dataOutputStream.writeUTF(encryptedPassword);
                dataOutputStream.flush();
                String response = dataInputStream.readUTF();
                if (response.equals("success")) {
                    System.out.println("Login successful");
                    System.out.println("Enter your command: ");
                    String command = scanner.nextLine();
                    while (!command.equals("exit")) {
//                        String encryptedCommand = symmetricKey.encryptCommand(command);
//                        dataOutputStream.writeUTF(encryptedCommand);
//                        dataOutputStream.flush();
                        String encryptedResponse = dataInputStream.readUTF();
//                        String decryptedResponse = symmetricKey.decryptResponse(encryptedResponse);
//                        System.out.println(decryptedResponse);
                        System.out.println("Enter your command: ");
                        command = scanner.nextLine();
                    }
                    continueLoop = false;
                } else {
                    System.out.println("Login failed");
                }

            }

        } catch (IOException e) {
            logger.severe("Failed to connect to bank server");
            e.getMessage();
        }
    }

    public static void main(String[] args) {
        ATM atm = new ATM("localhost", 1234);
        atm.run();

    }
}
