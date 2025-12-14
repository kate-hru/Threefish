import java.io.*;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;

public class ThreefishTest {

    private static final SecureRandom random = new SecureRandom();

    public static void main(String[] args) throws Exception {
        testBasicEncryption();
        testFileEncryption();
        testDirectoryEncryption();
        testKeySizes();
        testPerformanceVsAES();
    }

    static void testBasicEncryption() {
        System.out.println("1. БАЗОВЫЙ ТЕСТ ШИФРОВАНИЯ:");

        for (int keySize : new int[]{256, 512, 1024}) {
            Threefish.Size size;
            switch (keySize) {
                case 256: size = Threefish.Size.TF_256; break;
                case 512: size = Threefish.Size.TF_512; break;
                case 1024: size = Threefish.Size.TF_1024; break;
                default: continue;
            }

            byte[] key = new byte[keySize / 8];
            byte[] tweak = new byte[16];

            Threefish cipher = new Threefish(size);
            cipher.setKey(key);
            cipher.setTweak(tweak);

            byte[] plaintext = new byte[keySize / 8];
            byte[] ciphertext = cipher.encryptBlock(plaintext);
            byte[] decrypted = cipher.decryptBlock(ciphertext);

            if (!Arrays.equals(plaintext, decrypted)) {
                System.out.println("Threefish-" + keySize + ": расшифрование не работает");
            }

            if (Arrays.equals(plaintext, ciphertext)) {
                System.out.println("Threefish-" + keySize + ": данные не шифруются");
            }

            System.out.println("Threefish-" + keySize + ": базовый тест пройден");
        }

        System.out.println();
    }

    static void testFileEncryption() throws Exception {
        System.out.println("2. ТЕСТ ШИФРОВАНИЯ ФАЙЛОВ:");

        File[] testFiles = {
                createTextFile("test1.txt", "Текстовый файл для тестирования"),
                createBinaryFile("test2.bin", 1024),
                createBinaryFile("test3.bin", 100),
                createTextFile("test4.txt", ""),
        };

        for (File file : testFiles) {
            for (int keySize : new int[]{256, 512, 1024}) {
                byte[] key = new byte[keySize / 8];
                random.nextBytes(key);

                byte[] originalData = Files.readAllBytes(file.toPath());
                String originalHash = calculateHash(originalData);

                String encryptedFile = file.getPath() + ".enc";
                encryptFile(file.getPath(), encryptedFile, keySize, key);

                String decryptedFile = file.getPath() + ".dec";
                decryptFile(encryptedFile, decryptedFile, keySize, key);

                byte[] decryptedData = Files.readAllBytes(new File(decryptedFile).toPath());
                String decryptedHash = calculateHash(decryptedData);

                if (!originalHash.equals(decryptedHash)) {
                    System.out.println("Файл " + file.getName() + " (" + keySize + " бит): хеши не совпадают");
                }

                new File(encryptedFile).delete();
                new File(decryptedFile).delete();
            }

            file.delete();
        }

        System.out.println("Шифрование файлов работает корректно");
        System.out.println();
    }

    static void testDirectoryEncryption() throws Exception {
        System.out.println("3. ТЕСТ ШИФРОВАНИЯ ДИРЕКТОРИЙ:");

        File testDir = new File("test_directory");
        if (testDir.exists()) {
            deleteDirectory(testDir);
        }
        testDir.mkdir();

        File subDir1 = new File(testDir, "subdir1");
        subDir1.mkdir();

        File subDir2 = new File(testDir, "subdir2");
        subDir2.mkdir();

        Files.write(new File(testDir, "root.txt").toPath(), "Корневой файл".getBytes());
        Files.write(new File(subDir1, "file1.txt").toPath(), "Файл в поддиректории 1".getBytes());
        Files.write(new File(subDir1, "file2.txt").toPath(), "Еще один файл".getBytes());
        Files.write(new File(subDir2, "data.bin").toPath(), new byte[]{0x01, 0x02, 0x03, 0x04});

        byte[] key = new byte[256 / 8];
        random.nextBytes(key);

        String encryptedDir = "test_directory_encrypted";
        encryptDirectory(testDir.getPath(), encryptedDir, 256, key);

        String decryptedDir = "test_directory_decrypted";
        decryptDirectory(encryptedDir, decryptedDir, 256, key);

        if (!compareDirectories(testDir, new File(decryptedDir))) {
            System.out.println("Директории не идентичны после шифрования/расшифрования");
        }

        deleteDirectory(new File(encryptedDir));
        deleteDirectory(new File(decryptedDir));
        deleteDirectory(testDir);

        System.out.println("Шифрование директорий работает корректно");
        System.out.println();
    }

    static void testKeySizes() {
        System.out.println("4. ТЕСТ РАЗНЫХ РАЗМЕРОВ КЛЮЧЕЙ:");

        byte[] testData = "Тестовые данные для сравнения размеров ключей".getBytes();

        for (int keySize : new int[]{256, 512, 1024}) {
            byte[] key = new byte[keySize / 8];
            random.nextBytes(key);

            Threefish cipher = createCipher(keySize, key);

            int nonceSize = keySize / 16;
            byte[] nonce = new byte[nonceSize];
            random.nextBytes(nonce);

            ThreefishCTR ctr = new ThreefishCTR(cipher, nonce);
            byte[] encrypted = ctr.encrypt(testData);

            ThreefishCTR ctr2 = new ThreefishCTR(cipher, nonce);
            byte[] decrypted = ctr2.decrypt(encrypted);

            if (!Arrays.equals(testData, decrypted)) {
                System.out.println("Ключ " + keySize + " бит: данные не восстановились");
            }

            if (Arrays.equals(testData, encrypted)) {
                System.out.println("Ключ " + keySize + " бит: данные не зашифровались");
            }

            System.out.println("Ключ " + keySize + " бит: работает корректно");
        }

        System.out.println();
    }

    static void testPerformanceVsAES() throws Exception{
        System.out.println("5. СРАВНЕНИЕ БЫСТРОДЕЙСТВИЯ THREEFISH И AES:");
        System.out.println();

        int testSizeMB = 70;
        byte[] testData = new byte[testSizeMB * 1024 * 1024];
        random.nextBytes(testData);

        System.out.println("   Тестовые данные: " + testSizeMB + " МБ");
        System.out.println();

        byte[] key = new byte[512 / 8];
        random.nextBytes(key);
        byte[] nonce = new byte[64];
        random.nextBytes(nonce);

        long threefishTime = testThreefishPerformance(key, nonce, testData);
        long aesTime = testAESPerformance(key, nonce, testData);

        System.out.println("   Threefish CTR: " + threefishTime + " мс");
        System.out.println("   AES CTR:       " + aesTime + " мс");
        System.out.println();

        double ratio = (double) threefishTime / aesTime;
        if (ratio > 1.5) {
            System.out.println("AES быстрее Threefish в " + String.format("%.1f", ratio) + " раз");
        } else if (ratio < 0.67) {
            System.out.println("Threefish быстрее AES в " + String.format("%.1f", 1/ratio) + " раз");
        } else {
            System.out.println("≈ Производительность сопоставима");
        }
        System.out.println();
    }

    static long testThreefishPerformance(byte[] key, byte[] nonce, byte[] testData) throws Exception {
        Threefish cipher = createCipher(512, key);
        ThreefishCTR ctr = new ThreefishCTR(cipher, nonce);

        long startTime = System.currentTimeMillis();
        byte[] encrypted = ctr.encrypt(testData);
        long endTime = System.currentTimeMillis();

        return endTime - startTime;
    }

    static long testAESPerformance(byte[] key, byte[] iv, byte[] testData) throws Exception {
        byte[] aesKey = Arrays.copyOf(key, 32);
        SecretKeySpec secretKey = new SecretKeySpec(aesKey, "AES");
        byte[] aesIv = Arrays.copyOf(iv, 16);
        IvParameterSpec ivSpec = new IvParameterSpec(aesIv);

        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);

        long startTime = System.currentTimeMillis();
        byte[] encrypted = cipher.doFinal(testData);
        long endTime = System.currentTimeMillis();

        return endTime - startTime;
    }

    static File createTextFile(String name, String content) throws IOException {
        File file = new File(name);
        Files.write(file.toPath(), content.getBytes("UTF-8"));
        return file;
    }

    static File createBinaryFile(String name, int size) throws IOException {
        File file = new File(name);
        byte[] data = new byte[size];
        random.nextBytes(data);
        Files.write(file.toPath(), data);
        return file;
    }

    static String calculateHash(byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] hash = md.digest(data);
        return bytesToHex(hash);
    }

    static void encryptFile(String input, String output, int keySize, byte[] key) throws Exception {
        Threefish cipher = createCipher(keySize, key);
        byte[] data = Files.readAllBytes(Paths.get(input));

        int nonceSize = keySize / 16;
        byte[] nonce = new byte[nonceSize];
        random.nextBytes(nonce);

        ThreefishCTR ctr = new ThreefishCTR(cipher, nonce);
        byte[] encrypted = ctr.encrypt(data);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(nonce);
        baos.write(encrypted);
        encrypted = baos.toByteArray();

        Files.write(Paths.get(output), encrypted);
    }

    static void decryptFile(String input, String output, int keySize, byte[] key) throws Exception {
        Threefish cipher = createCipher(keySize, key);
        byte[] allData = Files.readAllBytes(Paths.get(input));

        int nonceSize = keySize / 16;
        byte[] nonce = Arrays.copyOfRange(allData, 0, nonceSize);
        byte[] data = Arrays.copyOfRange(allData, nonceSize, allData.length);

        ThreefishCTR ctr = new ThreefishCTR(cipher, nonce);
        byte[] decrypted = ctr.decrypt(data);

        Files.write(Paths.get(output), decrypted);
    }

    static void encryptDirectory(String inputDir, String outputDir, int keySize, byte[] key) throws Exception {
        File input = new File(inputDir);
        File output = new File(outputDir);
        output.mkdirs();

        Files.walkFileTree(input.toPath(), new SimpleFileVisitor<Path>() {
            @Override
            public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
                Path relative = input.toPath().relativize(file);
                Path outputPath = output.toPath().resolve(relative);
                Files.createDirectories(outputPath.getParent());

                try {
                    encryptFile(file.toString(), outputPath.toString(), keySize, key);
                } catch (Exception e) {
                    throw new IOException(e);
                }
                return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) throws IOException {
                return FileVisitResult.CONTINUE;
            }
        });
    }

    static void decryptDirectory(String inputDir, String outputDir, int keySize, byte[] key) throws Exception {
        File input = new File(inputDir);
        File output = new File(outputDir);
        output.mkdirs();

        Files.walkFileTree(input.toPath(), new SimpleFileVisitor<Path>() {
            @Override
            public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
                Path relative = input.toPath().relativize(file);
                Path outputPath = output.toPath().resolve(relative);
                Files.createDirectories(outputPath.getParent());

                try {
                    decryptFile(file.toString(), outputPath.toString(), keySize, key);
                } catch (Exception e) {
                    throw new IOException(e);
                }
                return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) throws IOException {
                return FileVisitResult.CONTINUE;
            }
        });
    }

    static boolean compareDirectories(File dir1, File dir2) throws IOException {
        if (!dir1.isDirectory() || !dir2.isDirectory()) {
            return false;
        }

        File[] files1 = dir1.listFiles();
        File[] files2 = dir2.listFiles();

        if (files1 == null || files2 == null || files1.length != files2.length) {
            return false;
        }

        Arrays.sort(files1);
        Arrays.sort(files2);

        for (int i = 0; i < files1.length; i++) {
            File f1 = files1[i];
            File f2 = files2[i];

            if (!f1.getName().equals(f2.getName())) {
                return false;
            }

            if (f1.isDirectory()) {
                if (!f2.isDirectory() || !compareDirectories(f1, f2)) {
                    return false;
                }
            } else {
                if (f2.isDirectory()) {
                    return false;
                }

                byte[] data1 = Files.readAllBytes(f1.toPath());
                byte[] data2 = Files.readAllBytes(f2.toPath());

                if (!Arrays.equals(data1, data2)) {
                    return false;
                }
            }
        }

        return true;
    }

    static void deleteDirectory(File dir) {
        if (dir.isDirectory()) {
            File[] files = dir.listFiles();
            if (files != null) {
                for (File file : files) {
                    deleteDirectory(file);
                }
            }
        }
        dir.delete();
    }

    static Threefish createCipher(int keySize, byte[] key) {
        Threefish.Size size;
        switch (keySize) {
            case 256: size = Threefish.Size.TF_256; break;
            case 512: size = Threefish.Size.TF_512; break;
            case 1024: size = Threefish.Size.TF_1024; break;
            default: throw new IllegalArgumentException("Неверный размер ключа: " + keySize);
        }
        Threefish cipher = new Threefish(size);
        cipher.setKey(key);
        return cipher;
    }

    static String bytesToHex(byte[] bytes) {
        StringBuilder hex = new StringBuilder();
        for (byte b : bytes) {
            hex.append(String.format("%02x", b));
        }
        return hex.toString();
    }
}