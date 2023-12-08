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
