import java.io.*;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.*;
import java.util.*;

public class Main {

    enum Mode { CTR, CFB }

    public static void main(String[] args) throws Exception {
        if (args.length == 0 || args[0].equals("-h")) {
            printHelp();
            return;
        }

        Config config = parseArgs(args);
        validateConfig(config);
        execute(config);
    }

    static class Config {
        Mode mode = Mode.CTR;
        boolean encrypt = false;
        boolean decrypt = false;
        String key = null;
        String password = null;
        String iv = null;
        String nonce = null;
        String input = null;
        String output = null;
        int keySize = 256;
        boolean recursive = false;
        boolean verbose = false;
        boolean storeMetadata = true;
    }

    static Config parseArgs(String[] args) {
        Config config = new Config();

        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "-E": config.encrypt = true; break;
                case "-D": config.decrypt = true; break;
                case "-mode":
                    if (i + 1 < args.length) {
                        String m = args[++i].toUpperCase();
                        if (m.equals("CTR")) config.mode = Mode.CTR;
                        else if (m.equals("CFB")) config.mode = Mode.CFB;
                    }
                    break;
                case "-k": if (i + 1 < args.length) config.key = args[++i]; break;
                case "-p": if (i + 1 < args.length) config.password = args[++i]; break;
                case "-iv": if (i + 1 < args.length) config.iv = args[++i]; break;
                case "-n": if (i + 1 < args.length) config.nonce = args[++i]; break;
                case "-s": if (i + 1 < args.length) config.keySize = Integer.parseInt(args[++i]); break;
                case "-r": config.recursive = true; break;
                case "-v": config.verbose = true; break;
                case "-nomd": config.storeMetadata = false; break;
                default:
                    if (config.input == null) config.input = args[i];
                    else if (config.output == null) config.output = args[i];
                    break;
            }
        }

        return config;
    }

    static void validateConfig(Config config) {
        if (!config.encrypt && !config.decrypt) {
            error("Укажите -E (шифрование) или -D (расшифрование)");
        }

        if (config.encrypt && config.decrypt) {
            error("Укажите либо -E, либо -D");
        }

        if (config.input == null) {
            error("Укажите входной файл/директорию");
        }

        File inputFile = new File(config.input);
        if (!inputFile.exists()) {
            error("Файл/директория не существует: " + config.input);
        }
    }

    static void execute(Config config) throws Exception {
        byte[] key = prepareKey(config);

        if (config.verbose) {
            System.out.println("Ключ: " + bytesToHex(key));
        }

        File input = new File(config.input);

        if (input.isFile()) {
            processFile(config, input, key);
        } else if (input.isDirectory()) {
            processDirectory(config, input, key);
        }

        if (config.verbose) {
            System.out.println("\nГотово!");
        }
    }

    static void processFile(Config config, File inputFile, byte[] key) throws Exception {
        if (config.verbose) {
            System.out.println((config.encrypt ? "Шифрование: " : "Расшифрование: ") + inputFile.getName());
        }

        byte[] data = Files.readAllBytes(inputFile.toPath());

        if (config.encrypt) {
            Threefish cipher = createCipher(config.keySize, key);
            byte[] result;
            byte[] iv = null;
            byte[] nonce = null;

            if (config.mode == Mode.CTR) {
                ThreefishCTR ctr = new ThreefishCTR(cipher);
                result = ctr.encrypt(data);
                nonce = ctr.getNonce();

                if (config.verbose) {
                    System.out.println("Nonce: " + bytesToHex(nonce));
                }
            } else {
                ThreefishCFB cfb = new ThreefishCFB(cipher);
                result = cfb.encrypt(data);
                iv = cfb.getIV();

                if (config.verbose) {
                    System.out.println("IV: " + bytesToHex(iv));
                }
            }

            String outputName = getOutputName(config, inputFile, true);
            if (config.storeMetadata) {
                saveWithMetadata(config, new File(outputName), result, key, iv, nonce);
            } else {
                Files.write(new File(outputName).toPath(), result);
            }

            System.out.println("Создан: " + outputName);

        } else {
            byte[] result;
            String outputName = getOutputName(config, inputFile, false);

            if (config.storeMetadata && inputFile.getName().endsWith(".enc")) {
                EncryptedFile meta = readEncryptedFile(inputFile);
                key = meta.key;

                Threefish cipher = createCipher(meta.keySize, key);

                if (meta.mode == Mode.CTR) {
                    ThreefishCTR ctr = new ThreefishCTR(cipher, meta.nonce);
                    result = ctr.decrypt(meta.data);
                } else {
                    ThreefishCFB cfb = new ThreefishCFB(cipher, meta.iv);
                    result = cfb.decrypt(meta.data);
                }
            } else {
                byte[] iv = (config.iv != null) ? hexToBytes(config.iv) : null;
                byte[] nonce = (config.nonce != null) ? hexToBytes(config.nonce) : null;

                Threefish cipher = createCipher(config.keySize, key);

                if (config.mode == Mode.CTR) {
                    ThreefishCTR ctr = new ThreefishCTR(cipher, nonce);
                    result = ctr.decrypt(data);
                } else {
                    ThreefishCFB cfb = new ThreefishCFB(cipher, iv);
                    result = cfb.decrypt(data);
                }
            }

            Files.write(new File(outputName).toPath(), result);
            System.out.println("Создан: " + outputName);
        }
    }

    static void processDirectory(Config config, File inputDir, byte[] key) throws Exception {
        String outputDir = getOutputDirName(config, inputDir);
        new File(outputDir).mkdirs();

        if (config.verbose) {
            System.out.println("Обработка директории: " + inputDir.getPath());
            System.out.println("Выходная директория: " + outputDir);
        }

        Files.walkFileTree(inputDir.toPath(), new SimpleFileVisitor<Path>() {
            @Override
            public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
                try {
                    if (!config.recursive && inputDir.toPath().relativize(file).getNameCount() > 1) {
                        return FileVisitResult.CONTINUE;
                    }

                    String name = file.getFileName().toString();
                    if (name.startsWith(".") || name.startsWith("~$")) {
                        return FileVisitResult.CONTINUE;
                    }

                    if (config.decrypt && !name.endsWith(".enc")) {
                        if (config.verbose) {
                            System.out.println("Пропущен (не .enc): " + name);
                        }
                        return FileVisitResult.CONTINUE;
                    }

                    Path relative = inputDir.toPath().relativize(file);
                    Path outputPath = Paths.get(outputDir).resolve(relative);
                    Files.createDirectories(outputPath.getParent());

                    Config fileConfig = new Config();
                    fileConfig.mode = config.mode;
                    fileConfig.encrypt = config.encrypt;
                    fileConfig.decrypt = config.decrypt;
                    fileConfig.key = config.key;
                    fileConfig.password = config.password;
                    fileConfig.iv = config.iv;
                    fileConfig.nonce = config.nonce;
                    fileConfig.keySize = config.keySize;
                    fileConfig.recursive = config.recursive;
                    fileConfig.verbose = config.verbose;
                    fileConfig.storeMetadata = config.storeMetadata;
                    fileConfig.input = file.toString();
                    fileConfig.output = outputPath.toString();

                    processFile(fileConfig, file.toFile(), key);

                } catch (Exception e) {
                    System.err.println("Ошибка: " + file + " - " + e.getMessage());
                }
                return FileVisitResult.CONTINUE;
            }
        });
    }

    static class EncryptedFile {
        byte[] data;
        byte[] key;
        byte[] iv;
        byte[] nonce;
        Mode mode;
        int keySize;
    }

    static void saveWithMetadata(Config config, File file, byte[] data, byte[] key, byte[] iv, byte[] nonce) throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(bos);

        dos.write("3FISH".getBytes("UTF-8"));
        dos.writeByte(1);
        dos.writeByte(config.mode.ordinal());
        dos.writeShort(config.keySize);
        dos.writeInt(data.length);

        if (config.mode == Mode.CTR) {
            dos.writeByte(1);
            dos.writeShort(nonce.length);
            dos.write(nonce);
        } else {
            dos.writeByte(2);
            dos.writeShort(iv.length);
            dos.write(iv);
        }

        dos.write(key);
        dos.write(data);

        Files.write(file.toPath(), bos.toByteArray());
    }

    static EncryptedFile readEncryptedFile(File file) throws Exception {
        byte[] all = Files.readAllBytes(file.toPath());

        if (all.length < 5 || !new String(all, 0, 5, "UTF-8").equals("3FISH")) {
            throw new Exception("Неверный формат файла (не Threefish)");
        }

        ByteArrayInputStream bis = new ByteArrayInputStream(all);
        DataInputStream dis = new DataInputStream(bis);

        EncryptedFile meta = new EncryptedFile();

        dis.skipBytes(5);
        int version = dis.readByte();
        if (version != 1) throw new Exception("Неподдерживаемая версия: " + version);

        meta.mode = Mode.values()[dis.readByte()];
        meta.keySize = dis.readShort();
        int dataLength = dis.readInt();

        int type = dis.readByte();
        int paramLength = dis.readShort();

        if (type == 1) {
            meta.nonce = new byte[paramLength];
            dis.readFully(meta.nonce);
        } else if (type == 2) {
            meta.iv = new byte[paramLength];
            dis.readFully(meta.iv);
        } else {
            throw new Exception("Неизвестный тип параметра: " + type);
        }

        int keyLength = meta.keySize / 8;
        meta.key = new byte[keyLength];
        dis.readFully(meta.key);
        meta.data = new byte[dataLength];
        dis.readFully(meta.data);

        return meta;
    }

    static byte[] prepareKey(Config config) throws Exception {
        if (config.key != null) {
            return hexToBytes(config.key);
        }

        if (config.password != null) {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(config.password.getBytes("UTF-8"));

            int needed = config.keySize / 8;
            if (hash.length >= needed) {
                return Arrays.copyOf(hash, needed);
            } else {
                ByteArrayOutputStream result = new ByteArrayOutputStream();
                result.write(hash);

                while (result.size() < needed) {
                    hash = md.digest(hash);
                    result.write(hash, 0, Math.min(hash.length, needed - result.size()));
                }

                return Arrays.copyOf(result.toByteArray(), needed);
            }
        }

        byte[] key = new byte[config.keySize / 8];
        new SecureRandom().nextBytes(key);
        return key;
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

    static String getOutputName(Config config, File inputFile, boolean encrypt) {
        if (config.output != null) return config.output;

        String name = inputFile.getName();
        if (encrypt) {
            return name + ".enc";
        } else {
            if (name.endsWith(".enc")) {
                return name.substring(0, name.length() - 4) + ".dec";
            } else {
                return name + ".dec";
            }
        }
    }

    static String getOutputDirName(Config config, File inputDir) {
        if (config.output != null) return config.output;
        return inputDir.getPath() + (config.encrypt ? "_encrypted" : "_decrypted");
    }

    static byte[] hexToBytes(String hex) {
        if (hex == null) return null;

        hex = hex.replaceAll("\\s+", "").toUpperCase();

        byte[] bytes = new byte[hex.length() / 2];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        }
        return bytes;
    }

    static String bytesToHex(byte[] bytes) {
        if (bytes == null) return "null";
        StringBuilder hex = new StringBuilder();
        for (byte b : bytes) {
            hex.append(String.format("%02X", b));
        }
        return hex.toString();
    }

    static void error(String message) {
        System.err.println("Ошибка: " + message);
        System.err.println("Используйте -h для справки");
        System.exit(1);
    }

    static void printHelp() {
        System.out.println("ОПЦИИ:");
        System.out.println("  -E             Шифрование");
        System.out.println("  -D             Расшифрование");
        System.out.println("  -mode CTR|CFB  Режим шифрования (по умолчанию: CTR)");
        System.out.println("  -k HEX         Ключ в HEX формате");
        System.out.println("  -p ПАРОЛЬ      Пароль");
        System.out.println("  -s 256|512|1024 Размер ключа (по умолчанию: 256)");
        System.out.println("  -n HEX         Nonce для CTR");
        System.out.println("  -iv HEX        IV для CFB");
        System.out.println("  -r             Рекурсивная обработка директорий");
        System.out.println("  -v             Подробный вывод");
        System.out.println("  -nomd          Не сохранять метаданные в .enc файлах");
        System.out.println();
    }
}
