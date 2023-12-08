import javax.crypto.Cipher;
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
    private final String bankServer;
    private final int bankPort;

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

                int publicKeyLength = dataInputStream.readInt();
                byte[] publicKeyBytes = new byte[publicKeyLength];
                dataInputStream.readFully(publicKeyBytes);

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
                        accountOperationMenu(socket, dataInputStream, dataOutputStream, scanner);
                    } else {
                        System.out.println("Please try again");
                    }
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

    private void accountOperationMenu(Socket socket, DataInputStream dataInputStream, DataOutputStream dataOutputStream, Scanner scanner) throws IOException {
        boolean continueLoop = true;
        while (continueLoop) {
            System.out.println("Choose an operation: ");
            System.out.println("1. Transfer money");
            System.out.println("2. Check account balance");
            System.out.println("3. Exit");
            System.out.println("Enter your choice: ");
            int choice = scanner.nextInt();
            scanner.nextLine();

            switch (choice) {
                case 1:
                    transferMoneyMenu(socket, dataInputStream, dataOutputStream, scanner);
                    break;
                case 2:
                    checkAccountBalanceMenu(socket, dataInputStream, dataOutputStream, scanner);
                    break;
                case 3:
                    continueLoop = false;
                    System.out.println("Thank you for using our ATM. Goodbye!");
                    closeConnection(socket, dataInputStream, dataOutputStream);
                    break;
                default:
                    System.out.println("Invalid choice. Please try again by entering 1, 2, or 3.");
                    accountOperationMenu(socket, dataInputStream, dataOutputStream, scanner);
            }
        }
    }

    private void closeConnection(Socket socket, DataInputStream dataInputStream, DataOutputStream dataOutputStream) {
        try {
            logger.info("Closing connection in 3 seconds");
            dataOutputStream.writeInt(3);
            dataOutputStream.flush();
            dataOutputStream.close();
            dataInputStream.close();
            socket.close();
            logger.info("Connection closed");
        } catch (IOException e) {
            logger.severe("Failed to send command to bank server");
            e.printStackTrace();
        }
    }

    private void checkAccountBalanceMenu(Socket socket, DataInputStream dataInputStream, DataOutputStream dataOutputStream, Scanner scanner) {
        try {
            dataOutputStream.writeInt(2);
            dataOutputStream.flush();

            String savingsAccountBalance = dataInputStream.readUTF();
            String checkingAccountBalance = dataInputStream.readUTF();

            System.out.println("Savings account balance: " + savingsAccountBalance);
            System.out.println("Checking account balance: " + checkingAccountBalance);
        } catch (IOException e) {
            logger.severe("Failed to send command to bank server");
            e.printStackTrace();
        }
    }

    private void transferMoneyMenu(Socket socket, DataInputStream dataInputStream, DataOutputStream dataOutputStream, Scanner scanner) {
        try {
            dataOutputStream.writeInt(1);
            dataOutputStream.flush();

            int accountType;
            double amount;

            while (true) {
                System.out.println("Enter the account type you want to transfer money from (1. Savings, 2. Checking): ");
                accountType = scanner.nextInt();
                scanner.nextLine();

                if (accountType == 1 || accountType == 2) {
                    break;  // Exit the loop if a valid account type is entered
                } else {
                    System.out.println("Incorrect input. Please enter 1 or 2.");
                }
            }

            System.out.println("Enter the recipient's ID: ");
            String recipientId = scanner.nextLine();

            while (true) {
                System.out.println("Enter the amount you want to transfer: ");
                amount = scanner.nextDouble();
                scanner.nextLine();

                if (amount >= 0) {
                    break;  // Exit the loop if a valid amount is entered
                } else {
                    System.out.println("Invalid amount. Please enter a non-negative value.");
                }
            }

            dataOutputStream.writeInt(recipientId.length());
            dataOutputStream.write(recipientId.getBytes(StandardCharsets.UTF_8));
            dataOutputStream.writeInt(accountType);
            dataOutputStream.writeDouble(amount);
            dataOutputStream.flush();

            String response = dataInputStream.readUTF();
            System.out.println(response);
        } catch (IOException e) {
            logger.severe("Failed to send command to bank server");
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

    public static void main(String[] args) {
        if (args.length != 2) {
            System.out.println("Usage: java Cli <host> <port>");
            System.exit(1);
        }

        String host = args[0];

        if (host.equals("localhost") || host.isEmpty()) {
            System.out.println("The host name should not be localhost or empty");
            System.exit(1);
        }

        int port = Integer.parseInt(args[1]);

        if (port < 1024 || port > 65535) {
            System.out.println("The port number should be a user-defined number between 1024 and 65535");
            System.exit(1);
        }
        ATM atm = new ATM(host, port);
        atm.run();
    }
}
