import javax.crypto.Cipher;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;

public class Bank {
    private final int port;


    String publicKeyFilePath;
    String privateKeyFilePath;
    private static PublicKey publicKey;
    private static PrivateKey privateKey;

    private static final Logger logger = Logger.getLogger(Bank.class.getName());

    public Bank(int port) {
        this.port = port;
        publicKeyFilePath = "public_key.pem";
        privateKeyFilePath = "private_key_pkcs8.pem";
        setPublicKey(publicKeyFilePath);
        setPrivateKey(privateKeyFilePath);
    }

    public static PrivateKey getPrivateKey() {
        return privateKey;
    }

    static void setPrivateKey(String privateKeyFilePath) {
        try {
            byte[] privateKeyBytes = Files.readAllBytes(new File(privateKeyFilePath).toPath());
            String privateKeyString = new String(privateKeyBytes);

            privateKeyString = privateKeyString.replace("-----BEGIN PRIVATE KEY-----\n", "")
                    .replace("-----END PRIVATE KEY-----", "")
                    .replaceAll("\\s", "");

            byte[] decodedPrivateKeyBytes = java.util.Base64.getDecoder().decode(privateKeyString);
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decodedPrivateKeyBytes);
            privateKey = KeyFactory.getInstance("RSA").generatePrivate(keySpec);
        } catch (Exception e) {
            logger.severe("Failed to read private key from file");
            e.getMessage();
        }
    }


    public static void main(String[] args) {
        if (args.length != 1) {
            System.out.println("Usage: java Bank <port>");
            System.exit(1);
        }
        int port = Integer.parseInt(args[0]);

        if (port < 1024 || port > 65535) {
            System.out.println("Invalid port number. Port number must be between 1024 and 65535");
            System.exit(1);
        }

        Bank bank = new Bank(port);
        bank.start();
    }

    private void start() {
        try (ServerSocket serverSocket = new ServerSocket(port)) {
            System.out.println("Server started. Listening on port " + port);
            while (true) {
                try {
                    Socket clientSocket = serverSocket.accept();
                    System.out.println("Client connected: " + clientSocket.getInetAddress());
                    new Thread(new BankThread(clientSocket, getPublicKey(), getPrivateKey())).start();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static PublicKey getPublicKey() {
        return publicKey;
    }

    public static void setPublicKey(String publicKeyFilePath) {
        try {
            byte[] publicKeyBytes = Files.readAllBytes(new File(publicKeyFilePath).toPath());
            String publicKeyString = new String(publicKeyBytes);

            publicKeyString = publicKeyString.replace("-----BEGIN PUBLIC KEY-----\n", "")
                    .replace("-----END PUBLIC KEY-----", "")
                    .replaceAll("\\s", "");

            byte[] decodedPublicKeyBytes = java.util.Base64.getDecoder().decode(publicKeyString);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decodedPublicKeyBytes);
            publicKey = java.security.KeyFactory.getInstance("RSA").generatePublic(keySpec);
        } catch (Exception e) {
            logger.severe("Failed to read public key from file");
            e.getMessage();
        }
    }


}

class BankThread implements Runnable {
    private final Socket socket;
    private String userId;
    Logger logger = Logger.getLogger(BankThread.class.getName());
    private PublicKey publicKey;
    private PrivateKey privateKey;

    public BankThread(Socket socket,PublicKey publicKey,PrivateKey privateKey){
        this.socket = socket;
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    @Override
    public void run() {
        while (true) {
            try (DataInputStream dataInputStream = new DataInputStream(socket.getInputStream());
                 DataOutputStream dataOutputStream = new DataOutputStream(socket.getOutputStream())) {
                logger.info("Connected to ATM");

                byte[] publicKeyBytes = convertPublicKeyToBytes(publicKey);
                dataOutputStream.writeInt(publicKeyBytes.length);
                dataOutputStream.write(publicKeyBytes);
                dataOutputStream.flush();

                boolean isAuthenticated = false;
                while (!isAuthenticated) {
                    int encryptedSymmetricKeyLength = dataInputStream.readInt();
                    byte[] encryptedSymmetricKeyBytes = new byte[encryptedSymmetricKeyLength];
                    dataInputStream.readFully(encryptedSymmetricKeyBytes);

                    String encryptedSymmetricKeyString = new String(encryptedSymmetricKeyBytes, StandardCharsets.UTF_8);
                    String symmetricKeyString = decryptWithPrivateKey(encryptedSymmetricKeyString, privateKey);

                    int encryptedIdLength = dataInputStream.readInt();
                    byte[] encryptedIdBytes = new byte[encryptedIdLength];
                    dataInputStream.readFully(encryptedIdBytes);
                    String encryptedId = new String(encryptedIdBytes, StandardCharsets.UTF_8);

                    int encryptedPasswordLength = dataInputStream.readInt();
                    byte[] encryptedPasswordBytes = new byte[encryptedPasswordLength];
                    dataInputStream.readFully(encryptedPasswordBytes);
                    String encryptedPassword = new String(encryptedPasswordBytes, StandardCharsets.UTF_8);

                    String id = SymmetricKey.decrypt(encryptedId, symmetricKeyString);
                    String password = SymmetricKey.decrypt(encryptedPassword, symmetricKeyString);

                    String passwordFilePath = "password";
                    String responseMessage = "";
                    BufferedReader bufferedReader = null;
                    try {
                        bufferedReader = new BufferedReader(new FileReader(passwordFilePath));
                        if (idAndPasswordMatch(bufferedReader, id, password)) {
                            responseMessage = "ID and password are correct";
                            byte[] responseMessageBytes = responseMessage.getBytes(StandardCharsets.UTF_8);
                            dataOutputStream.writeInt(responseMessage.length());
                            dataOutputStream.write(responseMessageBytes);
                            dataOutputStream.flush();
                            isAuthenticated = true;

                            while (true) {
                                int userChoice = dataInputStream.readInt();
                                System.out.println("User choice: " + userChoice);
                                switch (userChoice) {
                                    case 1:
                                        int recipientIdLength = dataInputStream.readInt();
                                        byte[] recipientIdBytes = new byte[recipientIdLength];
                                        dataInputStream.readFully(recipientIdBytes);
                                        String recipientId = new String(recipientIdBytes, StandardCharsets.UTF_8);
                                        int accountType = dataInputStream.readInt();
                                        double amount = dataInputStream.readDouble();

                                        String transferResponse = processAccountTransfer(id, accountType, recipientId, amount);
                                        dataOutputStream.writeUTF(transferResponse);
                                        dataOutputStream.flush();
                                        break;
                                    case 2:
                                        String[] accountBalance = fetchAccountBalance(id);
                                        dataOutputStream.writeUTF(accountBalance[0]);
                                        dataOutputStream.writeUTF(accountBalance[1]);
                                        dataOutputStream.flush();
                                        break;
                                    case 3:
                                        System.out.println("Disconnecting ATM");
//                                        closeConnection(socket, dataInputStream, dataOutputStream);
                                        return;
                                    default:
                                        System.out.println("Invalid choice");
                                        break;
                                }
                            }
                        } else {
                            responseMessage = "ID and password are incorrect";
                            byte[] responseMessageBytes = responseMessage.getBytes(StandardCharsets.UTF_8);
                            dataOutputStream.writeInt(responseMessage.length());
                            dataOutputStream.write(responseMessageBytes);
                            dataOutputStream.flush();
                        }
                    } catch (EOFException eofException) {
                        logger.severe("Connection ended");
                    } catch (FileNotFoundException e) {
                        logger.severe("Failed to read password file");
                        e.printStackTrace();
                    } finally {
                        if (bufferedReader != null) {
                            try {
                                bufferedReader.close();
                            } catch (IOException e) {
                                logger.severe("Failed to close bufferedReader");
                                e.printStackTrace();
                            }
                        }
                    }
                }
            } catch (EOFException eofException) {
                logger.severe("Connection ended");
            } catch (IOException e) {
                logger.severe("Failed to connect to ATM");
                e.printStackTrace();
            } finally {
                logger.info("Disconnected from ATM");
            }
        }
    }

    private void closeConnection(Socket socket, DataInputStream dataInputStream, DataOutputStream dataOutputStream) {
        try {
            logger.info("Closing connection to ATM");
            dataOutputStream.writeInt(0);
            socket.close();
            dataInputStream.close();
            dataOutputStream.close();
        } catch (IOException e) {
            logger.severe("Failed to close connection");
            e.printStackTrace();
        }
    }

    private String processAccountTransfer(String id, int accountType, String beneficiaryId, double amount) {
        logger.info("Processing account transfer");
        String response = "";
        final String balanceFilePath = "balance";

        if (checkBeneficiaryIDExists(beneficiaryId, balanceFilePath)) {
            Map<String, Map<String, Double>> balances = loadBalancesFromFile(balanceFilePath);

            if (balances.containsKey(id) && hasSufficientFunds(balances.get(id), accountType, amount)) {
                updateBalance(balances.get(id), accountType, -amount);

                updateBalance(balances.get(beneficiaryId), accountType, amount);

                saveBalancesToFile(balances, balanceFilePath);

                response = "Your transaction is successful";
            } else {
                response = "Your account does not have enough funds";
            }
        } else {
            response = "The recipient's ID does not exist";
        }

        return response;
    }

    private Map<String, Map<String, Double>> loadBalancesFromFile(String filePath) {
        Map<String, Map<String, Double>> balances = new HashMap<>();
        try (BufferedReader bufferedReader = new BufferedReader(new FileReader(filePath))) {
            String line;
            while ((line = bufferedReader.readLine()) != null) {
                String[] parts = line.split(" ");
                if (parts.length == 3) {
                    String id = parts[0];
                    double savingBalance = Double.parseDouble(parts[1]);
                    double checkingBalance = Double.parseDouble(parts[2]);

                    Map<String, Double> accountBalances = new HashMap<>();
                    accountBalances.put("savings", savingBalance);
                    accountBalances.put("checking", checkingBalance);

                    balances.put(id, accountBalances);
                }
            }
        } catch (IOException | NumberFormatException e) {
            logger.severe("Failed to load balances from file: " + e.getMessage());
        }
        return balances;
    }

    private void saveBalancesToFile(Map<String, Map<String, Double>> balances, String filePath) {
        try (BufferedWriter bufferedWriter = new BufferedWriter(new FileWriter(filePath))) {
            for (Map.Entry<String, Map<String, Double>> entry : balances.entrySet()) {
                bufferedWriter.write(entry.getKey());
                bufferedWriter.write(" " + entry.getValue().get("savings"));
                bufferedWriter.write(" " + entry.getValue().get("checking"));
                bufferedWriter.newLine();
            }
        } catch (IOException e) {
            logger.severe("Failed to save balances to file: " + e.getMessage());
        }
    }

    private boolean hasSufficientFunds(Map<String, Double> accountBalances, int accountType, double amount) {
        String accountTypeStr = accountType == 1 ? "savings" : "checking";
        return accountBalances.containsKey(accountTypeStr) && accountBalances.get(accountTypeStr) >= amount;
    }

    private void updateBalance(Map<String, Double> accountBalances, int accountType, double amount) {
        String accountTypeStr = accountType == 1 ? "savings" : "checking";
        double currentBalance = accountBalances.getOrDefault(accountTypeStr, 0.0);
        accountBalances.put(accountTypeStr, currentBalance + amount);
    }

    private boolean checkBeneficiaryIDExists(String beneficiaryId, String filePath) {
        try (BufferedReader bufferedReader = new BufferedReader(new FileReader(filePath))) {
            String line;
            while ((line = bufferedReader.readLine()) != null) {
                String[] parts = line.split(" ");
                if (parts.length > 0 && parts[0].equals(beneficiaryId)) {
                    return true;
                }
            }
        } catch (IOException e) {
            logger.severe("Failed to check beneficiary ID: " + e.getMessage());
        }
        return false;
    }

    private String[] fetchAccountBalance(String id) {
        BufferedReader bufferedReader = null;
        String[] accountBalance = new String[2];
        try {
            bufferedReader = new BufferedReader(new FileReader("balance"));
            String line = bufferedReader.readLine();
            while (line != null) {
                String[] accountBalanceArray = line.split(" ");
                String accountId = accountBalanceArray[0];
                String savingsAccountBalance = accountBalanceArray[1];
                String checkingAccountBalance = accountBalanceArray[2];

                if (id.equals(accountId)) {
                    accountBalance[0] = savingsAccountBalance;
                    accountBalance[1] = checkingAccountBalance;
                    break;
                }
                line = bufferedReader.readLine();
            }
        } catch (IOException ioException) {
            logger.severe("Failed to read account balance file");
            ioException.printStackTrace();
        }
        return accountBalance;
    }

    private boolean idAndPasswordMatch(BufferedReader bufferedReader, String id, String password) {
        boolean isAuthenticated = false;
        try {
            String line = bufferedReader.readLine();
            while (line != null) {
                String[] passwordFileContentArray = line.split(" ");
                String passwordFileId = passwordFileContentArray[0];
                String passwordFilePassword = passwordFileContentArray[1];

                if (id.equals(passwordFileId) && password.equals(passwordFilePassword)) {
                    logger.info("ID and password are correct");
                    isAuthenticated = true;
                    this.userId = id;
                    break;  // No need to check further once a match is found
                }
                line = bufferedReader.readLine();
            }
        } catch (IOException ioException) {
            logger.severe("Failed to read password file");
            ioException.printStackTrace();
        }
        return isAuthenticated;
    }

    private String decryptWithPrivateKey(String encryptedSymmetricKeyString, PrivateKey privateKey) {
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] cipherText = cipher.doFinal(Base64.getDecoder().decode(encryptedSymmetricKeyString));
            return new String(cipherText);
        } catch (Exception e) {
            logger.severe("Failed to decrypt");
            return null;
        }
    }

    private byte[] convertPublicKeyToBytes(PublicKey publicKey) {
        return publicKey.getEncoded();
    }
}
