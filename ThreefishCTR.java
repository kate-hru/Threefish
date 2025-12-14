import java.util.Arrays;
import java.security.SecureRandom;

public class ThreefishCTR {
    private final Threefish cipher;
    private final int blockSize;
    private final byte[] nonce;
    private long counter;

    public ThreefishCTR(Threefish cipher) {
        this.cipher = cipher;
        this.blockSize = cipher.size.blockBytes;
        this.nonce = generateRandomNonce();
        this.counter = 0L;
    }

    private byte[] generateRandomNonce() {
        SecureRandom random = new SecureRandom();
        int nonceSize = blockSize / 2;
        byte[] nonceBytes = new byte[nonceSize];
        random.nextBytes(nonceBytes);
        return nonceBytes;
    }

    private byte[] createCounterBlock(long counterValue) {
        byte[] counterBlock = new byte[blockSize];

        System.arraycopy(nonce, 0, counterBlock, 0, nonce.length);

        for (int i = 0; i < 8; i++) {
            int position = nonce.length + i;
            if (position < blockSize) {
                counterBlock[position] = (byte) (counterValue >>> (i * 8));
            }
        }

        for (int i = nonce.length + 8; i < blockSize; i++) {
            counterBlock[i] = 0;
        }

        return counterBlock;
    }

    public ThreefishCTR(Threefish cipher, byte[] nonce) {
        this.cipher = cipher;
        this.blockSize = cipher.size.blockBytes;

        if (nonce == null || nonce.length < blockSize / 2) {
            throw new IllegalArgumentException("Nonce должен быть не менее " + (blockSize / 2) + " байт");
        }

        this.nonce = Arrays.copyOf(nonce, Math.min(nonce.length, blockSize / 2));
        this.counter = 0L;
    }

    public byte[] getNonce() {
        return nonce.clone();
    }

    public long getCounter() {
        return counter;
    }

    public void resetCounter() {
        this.counter = 0L;
    }

    public byte[] process(byte[] data) {
        if (data == null || data.length == 0) {
            return new byte[0];
        }

        byte[] result = new byte[data.length];
        long currentCounter = counter;
        int processed = 0;

        while (processed < data.length) {
            byte[] counterBlock = createCounterBlock(currentCounter);
            byte[] keystream = cipher.encryptBlock(counterBlock);
            int bytesToProcess = Math.min(blockSize, data.length - processed);
            for (int i = 0; i < bytesToProcess; i++) {
                result[processed + i] = (byte) (data[processed + i] ^ keystream[i]);
            }
            processed += bytesToProcess;
            currentCounter++;
        }

        counter = currentCounter;

        return result;
    }

    public byte[] encrypt(byte[] plaintext) {
        return process(plaintext);
    }

    public byte[] decrypt(byte[] ciphertext) {
        return process(ciphertext);
    }
}
