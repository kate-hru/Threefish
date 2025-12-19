public class Threefish {

    private static final long C240 = 0x1BD11BDAA9FC1A22L;

    public enum Size {
        TF_256(4, 32, 32, 72),
        TF_512(8, 64, 64, 72),
        TF_1024(16, 128, 128, 80);

        final int Nw;
        final int blockBytes;
        final int keyBytes;
        final int rounds;

        Size(int Nw, int blockBytes, int keyBytes, int rounds) {
            this.Nw = Nw;
            this.blockBytes = blockBytes;
            this.keyBytes = keyBytes;
            this.rounds = rounds;
        }
    }

    public Size size;
    private long[] expandedKey;
    private long[] expandedTweak = new long[3];
    private boolean keySet = false;

    private static final int[][] ROTATIONS_256 = {
            {14, 16},
            {52, 57},
            {23, 40},
            {5, 37},
            {25, 33},
            {46, 12},
            {58, 22},
            {32, 32}
    };

    private static final int[][] ROTATIONS_512 = {
            {46, 36, 19, 37},
            {33, 27, 14, 42},
            {17, 49, 36, 39},
            {44, 9, 54, 56},
            {39, 30, 34, 24},
            {13, 50, 10, 17},
            {25, 29, 39, 43},
            {8, 35, 56, 22}
    };

    private static final int[][] ROTATIONS_1024 = {
            {24, 13, 8, 47, 8, 17, 22, 37},
            {38, 19, 10, 55, 49, 18, 23, 52},
            {33, 4, 51, 13, 34, 41, 59, 17},
            {5, 20, 48, 41, 47, 28, 16, 25},
            {41, 9, 37, 31, 12, 47, 44, 30},
            {16, 34, 56, 51, 4, 53, 42, 41},
            {31, 44, 47, 46, 19, 42, 44, 25},
            {9, 48, 35, 52, 23, 31, 37, 20}
    };

    public Threefish(Size size) {
        this.size = size;
        this.expandedKey = new long[size.Nw + 1];
    }

    public void setKey(byte[] key) {
        if (key.length != size.keyBytes) {
            throw new IllegalArgumentException(
                    "Ключ должен быть" + size.keyBytes + " байт для " + size
            );
        }

        long[] keyWords = bytesToLong(key, size.Nw);

        for (int i = 0; i < size.Nw; i++) {
            expandedKey[i] = keyWords[i];
        }

        // Вычисляем K[Nw] = C240 ⊕ (K[0] ⊕ K[1] ⊕ ... ⊕ K[Nw-1])
        expandedKey[size.Nw] = C240;
        for (int i = 0; i < size.Nw; i++) {
            expandedKey[size.Nw] ^= keyWords[i];
        }

        keySet = true;
    }

    public void setTweak(byte[] tweak) {
        if (tweak.length != 16) {
            throw new IllegalArgumentException("Tweak-значение должно быть 16 байт");
        }

        long t0 = 0, t1 = 0;
        for (int i = 0; i < 8; i++) {
            t0 |= (tweak[i] & 0xFFL) << (i * 8);
            t1 |= (tweak[i + 8] & 0xFFL) << (i * 8);
        }

        expandedTweak[0] = t0;
        expandedTweak[1] = t1;
        expandedTweak[2] = t0 ^ t1;
    }


    public byte[] encryptBlock(byte[] block) {
        if (!keySet) {
            throw new IllegalStateException("Ключ не установлен");
        }
        if (block.length != size.blockBytes) {
            throw new IllegalArgumentException(
                    "Блок должен быть " + size.blockBytes + " байт"
            );
        }

        long[] state = bytesToLong(block, size.Nw);
        addKey(state, 0);

        for (int r = 0; r < size.rounds; r++) {
            if (r % 4 == 0 && r > 0) {
                addKey(state, r / 4);
            }

            if (size == Size.TF_256) {
                mix256(state, r);
            } else if (size == Size.TF_512) {
                mix512(state, r);
            } else {
                mix1024(state, r);
            }

            if (size == Size.TF_256) {
                permute256(state);
            } else if (size == Size.TF_512) {
                permute512(state);
            } else {
                permute1024(state);
            }

        }

        addKey(state, size.rounds / 4);

        return longsToBytes(state);
    }


    public byte[] decryptBlock(byte[] block) {
        if (!keySet) {
            throw new IllegalStateException("Ключ не установлен");
        }
        if (block.length != size.blockBytes) {
            throw new IllegalArgumentException(
                    "Блок должен быть " + size.blockBytes + " байт"
            );
        }

        long[] state = bytesToLong(block, size.Nw);

        subtractKey(state, size.rounds / 4);

        for (int r = size.rounds - 1; r >= 0; r--) {
            if (size == Size.TF_256) {
                permute256(state);
            } else if (size == Size.TF_512) {
                inversePermute512(state);
            } else {
                inversePermute1024(state);
            }

            if (size == Size.TF_256) {
                inverseMix256(state, r);
            } else if (size == Size.TF_512) {
                inverseMix512(state, r);
            } else {
                inverseMix1024(state, r);
            }


            if (r % 4 == 0 && r > 0) {
                subtractKey(state, r / 4);
            }
        }

        subtractKey(state, 0);

        return longsToBytes(state);
    }


    private void addKey(long[] state, int s) {
        int keyWords = size.Nw + 1;

        for (int i = 0; i <= size.Nw - 4; i++) {
            state[i] += expandedKey[(s + i) % keyWords];
        }

        state[size.Nw - 3] += expandedKey[(s + size.Nw - 3) % keyWords] + expandedTweak[s % 3];
        state[size.Nw - 2] += expandedKey[(s + size.Nw - 2) % keyWords] + expandedTweak[(s + 1) % 3];
        state[size.Nw - 1] += expandedKey[(s + size.Nw - 1) % keyWords] + s;
    }

    private void subtractKey(long[] state, int s) {
        int keyWords = size.Nw + 1;

        state[size.Nw - 1] -= expandedKey[(s + size.Nw - 1) % keyWords] + s;
        state[size.Nw - 2] -= expandedKey[(s + size.Nw - 2) % keyWords] + expandedTweak[(s + 1) % 3];
        state[size.Nw - 3] -= expandedKey[(s + size.Nw - 3) % keyWords] + expandedTweak[s % 3];

        for (int i = size.Nw - 4; i >= 0; i--) {
            state[i] -= expandedKey[(s + i) % keyWords];
        }
    }


    private void mix256(long[] state, int round) {
        int d = round % 8;
        int r0 = ROTATIONS_256[d][0];
        int r1 = ROTATIONS_256[d][1];

        state[0] = state[0] + state[1];
        state[1] = Long.rotateLeft(state[1], r0) ^ state[0];

        state[2] = state[2] + state[3];
        state[3] = Long.rotateLeft(state[3], r1) ^ state[2];
    }

    private void inverseMix256(long[] state, int round) {
        int d = round % 8;
        int r0 = ROTATIONS_256[d][0];
        int r1 = ROTATIONS_256[d][1];

        state[3] = Long.rotateRight(state[3] ^ state[2], r1);
        state[2] = state[2] - state[3];

        state[1] = Long.rotateRight(state[1] ^ state[0], r0);
        state[0] = state[0] - state[1];
    }

    private void mix512(long[] state, int round) {
        int d = round % 8;

        for (int p = 0; p < 4; p++) {
            int i = p * 2;
            int j = p * 2 + 1;
            int rotation = ROTATIONS_512[d][p];

            state[i] = state[i] + state[j];
            state[j] = Long.rotateLeft(state[j], rotation) ^ state[i];
        }
    }

    private void inverseMix512(long[] state, int round) {
        int d = round % 8;

        for (int p = 3; p >= 0; p--) {
            int i = p * 2;
            int j = p * 2 + 1;
            int rotation = ROTATIONS_512[d][p];

            state[j] = Long.rotateRight(state[j] ^ state[i], rotation);
            state[i] = state[i] - state[j];
        }
    }

    private void mix1024(long[] state, int round) {
        int d = round % 8;

        for (int p = 0; p < 8; p++) {
            int i = p * 2;
            int j = p * 2 + 1;
            int rotation = ROTATIONS_1024[d][p];

            state[i] = state[i] + state[j];
            state[j] = Long.rotateLeft(state[j], rotation) ^ state[i];
        }
    }

    private void inverseMix1024(long[] state, int round) {
        int d = round % 8;

        for (int p = 7; p >= 0; p--) {
            int i = p * 2;
            int j = p * 2 + 1;
            int rotation = ROTATIONS_1024[d][p];

            state[j] = Long.rotateRight(state[j] ^ state[i], rotation);
            state[i] = state[i] - state[j];
        }
    }


    private void permute256(long[] state) {
        // [0 1 2 3] -> [0 3 2 1]
        long temp = state[1];
        state[1] = state[3];
        state[3] = temp;
    }

    private void permute512(long[] state) {
        // [0 1 2 3 4 5 6 7] -> [2 1 4 7 6 5 0 3]
        long[] temp = state.clone();
        state[0] = temp[2];
        state[1] = temp[1];
        state[2] = temp[4];
        state[3] = temp[7];
        state[4] = temp[6];
        state[5] = temp[5];
        state[6] = temp[0];
        state[7] = temp[3];
    }

    private void inversePermute512(long[] state) {
        // [0 1 2 3 4 5 6 7] <- [2 1 4 7 6 5 0 3]
        long[] temp = state.clone();
        state[0] = temp[6];
        state[1] = temp[1];
        state[2] = temp[0];
        state[3] = temp[7];
        state[4] = temp[2];
        state[5] = temp[5];
        state[6] = temp[4];
        state[7] = temp[3];
    }

    private void permute1024(long[] state) {
        // [0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15] -> [0 9 2 13 6 11 4 15 10 7 12 3 14 5 8 1]
        long[] temp = state.clone();
        state[0] = temp[0];
        state[1] = temp[9];
        state[2] = temp[2];
        state[3] = temp[13];
        state[4] = temp[6];
        state[5] = temp[11];
        state[6] = temp[4];
        state[7] = temp[15];
        state[8] = temp[10];
        state[9] = temp[7];
        state[10] = temp[12];
        state[11] = temp[3];
        state[12] = temp[14];
        state[13] = temp[5];
        state[14] = temp[8];
        state[15] = temp[1];
    }

    private void inversePermute1024(long[] state) {
        // [0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15] -> [0 9 2 13 6 11 4 15 10 7 12 3 14 5 8 1]
        long[] temp = state.clone();
        state[0] = temp[0];
        state[1] = temp[15];
        state[2] = temp[2];
        state[3] = temp[11];
        state[4] = temp[6];
        state[5] = temp[13];
        state[6] = temp[4];
        state[7] = temp[9];
        state[8] = temp[14];
        state[9] = temp[1];
        state[10] = temp[8];
        state[11] = temp[5];
        state[12] = temp[10];
        state[13] = temp[3];
        state[14] = temp[12];
        state[15] = temp[7];
    }


    public long[] bytesToLong(byte[] bytes, int numLongs) {
        long[] longs = new long[numLongs];

        for (int i = 0; i < numLongs; i++) {
            long value = 0;
            for (int j = 0; j < 8; j++) {
                int idx = i * 8 + j;
                if (idx < bytes.length) {
                    long b = bytes[idx] & 0xFFL;
                    value |= b << (j * 8);
                }
            }
            longs[i] = value;
        }
        return longs;
    }


    public byte[] longsToBytes(long[] longs) {
        byte[] bytes = new byte[longs.length * 8];

        for (int i = 0; i < longs.length; i++) {
            for (int j = 0; j < 8; j++) {
                bytes[i * 8 + j] = (byte) ((longs[i] >> (j * 8)) & 0xFF);
            }
        }

        return bytes;
    }
}
