import javax.crypto.Cipher;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
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
        try {
            try (Socket socket = new Socket(bankServer, bankPort)) {
                DataInputStream dataInputStream = new DataInputStream(socket.getInputStream());
                DataOutputStream dataOutputStream = new DataOutputStream(socket.getOutputStream());
                logger.info("Connected to bank server");
//            receive bank's public key
                int publicKeyLength = dataInputStream.readInt();

                // Receive the public key as a byte array
                byte[] publicKeyBytes = new byte[publicKeyLength];
                dataInputStream.readFully(publicKeyBytes);

                // Convert the byte array to a PublicKey object
                PublicKey publicKey = convertBytesToPublicKey(publicKeyBytes);
                logger.info("Received bank's public key");

                Scanner scanner = new Scanner(System.in);
                boolean continueLoop = true;
                while (continueLoop) {
                    System.out.println("Enter your ID: ");
                    String id = scanner.nextLine();
                    System.out.println("Enter your password: ");
                    String password = scanner.nextLine();

                    SymmetricKey symmetricKey = new SymmetricKey();
                    String symmetricKeyString = symmetricKey.getSymmetricKeyString();

                    String encryptedSymmetricKeyString = encryptWithPublicKey(symmetricKeyString, publicKey);
                    String encryptedId = symmetricKey.encryptId(id);
                    String encryptedPassword = symmetricKey.encryptPassword(password);

                    assert encryptedSymmetricKeyString != null;
                    dataOutputStream.writeInt(encryptedSymmetricKeyString.length());
                    dataOutputStream.write(encryptedSymmetricKeyString.getBytes(StandardCharsets.UTF_8));

                    dataOutputStream.writeInt(encryptedId.length());
                    dataOutputStream.write(encryptedId.getBytes(StandardCharsets.UTF_8));
                    dataOutputStream.writeInt(encryptedPassword.length());
                    dataOutputStream.write(encryptedPassword.getBytes(StandardCharsets.UTF_8));
                    dataOutputStream.flush();

                    int responseLength = dataInputStream.readInt();
                    byte[] responseBytes = new byte[responseLength];
                    dataInputStream.readFully(responseBytes);
                    String response = new String(responseBytes, StandardCharsets.UTF_8);
                    System.out.println(response);

                    if (response.equals("ID and password are correct")) {
                        continueLoop = false;
                    }
                }
                while (true) {
                    System.out.println("Please select one of the following actions (enter 1, 2, or 3):");
                    System.out.println("1. Transfer money");
                    System.out.println("2. Check account balance");
                    System.out.println("3. Exit");

                    int choice = scanner.nextInt();
                    switch (choice) {
                        case 1:
                            System.out.println("Transfer money option selected");
                            // Implement transfer money logic
                            break;
                        case 2:
                            System.out.println("Check account balance option selected");
                            // Implement check account balance logic
                            break;
                        case 3:
                            System.out.println("Exiting...");
                            break;
                        default:
                            System.out.println("Invalid choice. Please enter 1, 2, or 3.");
                            continue;
                    }
                    break;
                }

            } catch (IOException e) {
                logger.severe("Failed to connect to bank server");
                e.printStackTrace();
            }

        } catch (Exception e) {
            logger.severe("Failed to connect to bank server");
            e.printStackTrace();
        }
    }

    private PublicKey convertBytesToPublicKey(byte[] publicKeyBytes) {
        try {
            // Convert the byte array to a PublicKey object
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
            return keyFactory.generatePublic(keySpec);
        } catch (Exception e) {
            logger.severe("Failed to convert bytes to public key");
            e.printStackTrace();
            return null;
        }
    }

    private String encryptWithPublicKey(String symmetricKeyString, PublicKey publicKey) {
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] cipherText = cipher.doFinal(symmetricKeyString.getBytes());
            return Base64.getEncoder().encodeToString(cipherText);
        } catch (Exception e) {
            logger.severe("Failed to encrypt with public key");
            e.printStackTrace();
            return null;
        }
    }

    private PublicKey convertStringToPublicKey(String publicKeyString) {
        try {
            byte[] keyBytes = Base64.getDecoder().decode(publicKeyString);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
            return KeyFactory.getInstance("RSA").generatePublic(keySpec);
        } catch (Exception e) {
            logger.severe("Failed to convert public key string to PublicKey");
            e.printStackTrace();
            return null;
        }
    }

    public static void main(String[] args) {
        ATM atm = new ATM("localhost", 1234);
        atm.run();

    }
}
