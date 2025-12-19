import java.security.SecureRandom;

public class ThreefishCFB {

    private final Threefish cipher;
    private final int blockSize;
    private byte[] iv;
    private byte[] feedback;

    public ThreefishCFB(Threefish cipher) {
        this.cipher = cipher;
        this.blockSize = cipher.size.blockBytes;
        this.iv = generateRandomIV();
        this.feedback = iv.clone();
    }

    public ThreefishCFB(Threefish cipher, byte[] iv) {
        this.cipher = cipher;
        this.blockSize = cipher.size.blockBytes;

        if (iv == null || iv.length != blockSize) {
            throw new IllegalArgumentException(
                    "IV должен быть ровно " + blockSize + " байт"
            );
        }

        this.iv = iv.clone();
        this.feedback = iv.clone();
    }

    private byte[] generateRandomIV() {
        byte[] iv = new byte[blockSize];
        new SecureRandom().nextBytes(iv);
        return iv;
    }

    public byte[] getIV() {
        return iv.clone();
    }

    public byte[] encrypt(byte[] plaintext) {
        if (plaintext == null || plaintext.length == 0) {
            return new byte[0];
        }

        byte[] ciphertext = new byte[plaintext.length];
        int feedbackPos = 0;

        for (int i = 0; i < plaintext.length; i++) {
            if (feedbackPos == 0) {
                feedback = cipher.encryptBlock(feedback);
            }

            ciphertext[i] = (byte) (plaintext[i] ^ feedback[feedbackPos]);
            feedback[feedbackPos] = ciphertext[i];
            feedbackPos = (feedbackPos + 1) % blockSize;
        }

        return ciphertext;
    }

    public byte[] decrypt(byte[] ciphertext) {
        if (ciphertext == null || ciphertext.length == 0) {
            return new byte[0];
        }

        byte[] plaintext = new byte[ciphertext.length];
        int feedbackPos = 0;

        for (int i = 0; i < ciphertext.length; i++) {
            if (feedbackPos == 0) {
                feedback = cipher.encryptBlock(feedback);
            }

            plaintext[i] = (byte) (ciphertext[i] ^ feedback[feedbackPos]);
            feedback[feedbackPos] = ciphertext[i];
            feedbackPos = (feedbackPos + 1) % blockSize;
        }

        return plaintext;
    }
}
