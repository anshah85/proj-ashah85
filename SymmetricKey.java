import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.logging.Logger;

public class SymmetricKey {
    private final SecretKey symmetricKey;

    private static final Logger logger = Logger.getLogger(SymmetricKey.class.getName());

    public SymmetricKey() {
        this.symmetricKey = generateSymmetricKey();
    }

    public SecretKey getSymmetricKey() {
        return symmetricKey;
    }

    public String getSymmetricKeyString() {
        return Base64.getEncoder().encodeToString(symmetricKey.getEncoded());
    }

    private SecretKey generateSymmetricKey() {
        String algorithm = "AES";
        int keySize = 256;

        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance(algorithm);
            keyGenerator.init(keySize);
            return keyGenerator.generateKey();
        } catch (NoSuchAlgorithmException noSuchAlgorithmException) {
            logger.severe("Failed to generate symmetric key");
            return null;
        }
    }

    public String encryptId(String id) {
        return encrypt(id, symmetricKey);
    }

    public String encryptPassword(String password) {
        return encrypt(password, symmetricKey);
    }
//
//    public String encryptCommand(String command) {
//        return encrypt(command, symmetricKey);
//    }
//
//    public String encryptSymmetricKeyString(String symmetricKeyString) {
//        return encrypt(symmetricKeyString, Bank.getPublicKey());
//    }

    public String encrypt(String plainText, SecretKey secretKey) {
        try {
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] cipherText = cipher.doFinal(plainText.getBytes());
            return Base64.getEncoder().encodeToString(cipherText);
        } catch (Exception e) {
            logger.severe("Failed to encrypt");
            return null;
        }
    }
}