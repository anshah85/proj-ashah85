import javax.crypto.Cipher;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
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
        Bank bank = new Bank(1234);
        bank.run();
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

    public void run() {
        try {
            ServerSocket serverSocket = new ServerSocket(port);
            logger.info("Bank server started");
            while (true) {
                try (Socket socket = serverSocket.accept();
                     DataInputStream dataInputStream = new DataInputStream(socket.getInputStream());
                     DataOutputStream dataOutputStream = new DataOutputStream(socket.getOutputStream())) {
                    logger.info("Connected to ATM");
//                    send public key to ATM
                    byte[] publicKeyBytes = convertPublicKeyToBytes(getPublicKey());

                    // Send the public key to ATM
                    dataOutputStream.writeInt(publicKeyBytes.length);
                    dataOutputStream.write(publicKeyBytes);
                    dataOutputStream.flush();

                    // Receive the encrypted symmetric key from ATM
                    int encryptedSymmetricKeyLength = dataInputStream.readInt();
                    byte[] encryptedSymmetricKeyBytes = new byte[encryptedSymmetricKeyLength];
                    dataInputStream.readFully(encryptedSymmetricKeyBytes);

                    // Decrypt the symmetric key using the private key
                    String encryptedSymmetricKeyString = new String(encryptedSymmetricKeyBytes, "UTF-8");
                    logger.info("Encrypted symmetric key string: " + encryptedSymmetricKeyString);
                    String symmetricKeyString = decryptWithPrivateKey(encryptedSymmetricKeyString, getPrivateKey());
                    logger.info("Symmetric key string: " + symmetricKeyString);

//                    receive encrypted userid and password from ATM
                    int encryptedIdLength = dataInputStream.readInt();
                    byte[] encryptedIdBytes = new byte[encryptedIdLength];
                    dataInputStream.readFully(encryptedIdBytes);
                    String encryptedId = new String(encryptedIdBytes, "UTF-8");
                    logger.info("Encrypted ID: " + encryptedId);

                    int encryptedPasswordLength = dataInputStream.readInt();
                    byte[] encryptedPasswordBytes = new byte[encryptedPasswordLength];
                    dataInputStream.readFully(encryptedPasswordBytes);
                    String encryptedPassword = new String(encryptedPasswordBytes, "UTF-8");
                    logger.info("Encrypted password: " + encryptedPassword);

//                    decrypt userid and password
                    String id = SymmetricKey.decrypt(encryptedId, symmetricKeyString);
                    String password = SymmetricKey.decrypt(encryptedPassword, symmetricKeyString);
                    logger.info("ID: " + id);
                    logger.info("Password: " + password);

//                    compares the ID and the password against the one stored in file “password”
                    String passwordFilePath = "password";
                    String responseMessage = "";
                    BufferedReader bufferedReader = null;
                    try {
                        bufferedReader = new BufferedReader(new FileReader(passwordFilePath));
                        if (idAndPasswordMatch(bufferedReader, id, password)) {
                            logger.info("ID and password are correct");
                            responseMessage = "ID and password are correct";
                            byte[] responseMessageBytes = responseMessage.getBytes(StandardCharsets.UTF_8);
                            dataOutputStream.writeInt(responseMessage.length());
                            dataOutputStream.write(responseMessageBytes);
                            dataOutputStream.flush();
                        } else {
                            logger.info("ID and password are incorrect");
                            responseMessage = "ID and password are incorrect";
                            byte[] responseMessageBytes = responseMessage.getBytes(StandardCharsets.UTF_8);
                            dataOutputStream.writeInt(responseMessage.length());
                            dataOutputStream.write(responseMessageBytes);
                            dataOutputStream.flush();
                        }
                    } catch (FileNotFoundException e) {
                        logger.severe("Failed to read password file");
                        e.printStackTrace();
                    }
//                    String passwordFileContent = new String(Files.readAllBytes(new File(passwordFilePath).toPath()));
//                    String[] passwordFileLines = passwordFileContent.split("\n");
//
//                    boolean isAuthenticated = false;
//
//                    for (String line : passwordFileLines) {
//                        String[] passwordFileContentArray = line.split(" ");
//                        String passwordFileId = passwordFileContentArray[0];
//                        String passwordFilePassword = passwordFileContentArray[1];
//
//                        if (id.equals(passwordFileId) && password.equals(passwordFilePassword)) {
//                            logger.info("ID and password are correct");
//                            isAuthenticated = true;
//                            break;  // No need to check further once a match is found
//                        }
//                    }
//
//                    String responseMessage = isAuthenticated ? "ID and password are correct" : "ID and password are incorrect";
//                    byte[] responseMessageBytes = responseMessage.getBytes(StandardCharsets.UTF_8);
//                    dataOutputStream.writeInt(responseMessage.length());
//                    dataOutputStream.write(responseMessageBytes);
//                    dataOutputStream.flush();

                } catch (IOException e) {
                    logger.severe("Failed to connect to ATM");
                    e.printStackTrace();
                }
            }
        } catch (IOException e) {
            logger.severe("Failed to start bank server");
            e.getMessage();
        }
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
