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

    public void reset() {
        this.feedback = iv.clone();
    }

    public byte[] process(byte[] data) {
        if (data == null || data.length == 0) {
            return new byte[0];
        }

        byte[] result = new byte[data.length];
        int feedbackPos = 0;

        for (int i = 0; i < data.length; i++) {
            if (feedbackPos == 0) {
                feedback = cipher.encryptBlock(feedback);
            }

            result[i] = (byte) (data[i] ^ feedback[feedbackPos]);
            feedback[feedbackPos] = data[i];
            feedbackPos = (feedbackPos + 1) % blockSize;
        }

        return result;
    }

    public byte[] encrypt(byte[] plaintext) {
        return process(plaintext);
    }

    public byte[] decrypt(byte[] ciphertext) {
        return process(ciphertext);
    }
}
