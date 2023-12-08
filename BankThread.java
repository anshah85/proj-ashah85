import javax.crypto.Cipher;
import java.io.*;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;

class BankThread implements Runnable {
    private final Socket socket;
    private String userId;
    Logger logger = Logger.getLogger(BankThread.class.getName());
    private final PublicKey publicKey;
    private final PrivateKey privateKey;

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
                        e.getMessage();
                    } finally {
                        if (bufferedReader != null) {
                            try {
                                bufferedReader.close();
                            } catch (IOException e) {
                                logger.severe("Failed to close bufferedReader");
                                e.getMessage();
                            }
                        }
                    }
                }
            } catch (EOFException eofException) {
                logger.severe("Connection ended");
            } catch (IOException e) {
                logger.severe("Failed to connect to ATM");
                e.getMessage();
            } finally {
                logger.info("Disconnected from ATM");
            }
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
            ioException.getMessage();
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
            ioException.getMessage();
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