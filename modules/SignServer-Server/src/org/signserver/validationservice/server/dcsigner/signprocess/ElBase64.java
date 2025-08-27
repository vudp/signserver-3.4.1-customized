package org.signserver.validationservice.server.dcsigner.signprocess;

public final class ElBase64
{
    public static String ERROR_INVALID_LENGTH;
    public static String ERROR_INVALID_CHAR;
    private static char[] encodeMatrix;
    private static byte[] decodeMatrix;
    
    public static byte[] decodeString(final String s) {
        int length = s.length();
        if (length % 4 != 0) {
            throw new IllegalArgumentException(ElBase64.ERROR_INVALID_LENGTH);
        }
        while (length > 0 && s.charAt(length - 1) == '=') {
            --length;
        }
        final int n = length * 3 / 4;
        final byte[] array = new byte[n];
        int i = 0;
        int n2 = 0;
        while (i < length) {
            final char char1 = s.charAt(i++);
            final char char2 = s.charAt(i++);
            final char c = (i < length) ? s.charAt(i++) : 'A';
            final char c2 = (i < length) ? s.charAt(i++) : 'A';
            if (char1 > '\u007f' || char2 > '\u007f' || c > '\u007f' || c2 > '\u007f') {
                throw new IllegalArgumentException(ElBase64.ERROR_INVALID_CHAR);
            }
            final byte b = ElBase64.decodeMatrix[char1];
            final byte b2 = ElBase64.decodeMatrix[char2];
            final byte b3 = ElBase64.decodeMatrix[c];
            final byte b4 = ElBase64.decodeMatrix[c2];
            if (b < 0 || b2 < 0 || b3 < 0 || b4 < 0) {
                throw new IllegalArgumentException(ElBase64.ERROR_INVALID_CHAR);
            }
            final int n3 = b << 2 | b2 >>> 4;
            final int n4 = (b2 & 0xF) << 4 | b3 >>> 2;
            final int n5 = (b3 & 0x3) << 6 | b4;
            array[n2++] = (byte)n3;
            if (n2 < n) {
                array[n2++] = (byte)n4;
            }
            if (n2 >= n) {
                continue;
            }
            array[n2++] = (byte)n5;
        }
        return array;
    }
    
    public static String encodeString(final byte[] array) {
        final int length = array.length;
        final int n = (length * 4 + 2) / 3;
        final char[] array2 = new char[(length + 2) / 3 * 4];
        int n3;
        int n4;
        int n5;
        int n6;
        int n7;
        int n8;
        int n9;
        for (int i = 0, n2 = 0; i < length; n3 = (array[i++] & 0xFF), n4 = ((i < length) ? (array[i++] & 0xFF) : 0), n5 = ((i < length) ? (array[i++] & 0xFF) : 0), n6 = n3 >>> 2, n7 = ((n3 & 0x3) << 4 | n4 >>> 4), n8 = ((n4 & 0xF) << 2 | n5 >>> 6), n9 = (n5 & 0x3F), array2[n2++] = ElBase64.encodeMatrix[n6], array2[n2++] = ElBase64.encodeMatrix[n7], array2[n2] = ((n2 < n) ? ElBase64.encodeMatrix[n8] : '='), ++n2, array2[n2] = ((n2 < n) ? ElBase64.encodeMatrix[n9] : '='), ++n2) {}
        return new String(array2);
    }
    
    static {
        ElBase64.ERROR_INVALID_LENGTH = "Length of input data is not a multiple of 4";
        ElBase64.ERROR_INVALID_CHAR = "Invalid character in Base64 encoded data";
        ElBase64.encodeMatrix = new char[64];
        int n = 0;
        for (char c = 'A'; c <= 'Z'; ++c) {
            ElBase64.encodeMatrix[n++] = c;
        }
        for (char c2 = 'a'; c2 <= 'z'; ++c2) {
            ElBase64.encodeMatrix[n++] = c2;
        }
        for (char c3 = '0'; c3 <= '9'; ++c3) {
            ElBase64.encodeMatrix[n++] = c3;
        }
        ElBase64.encodeMatrix[n++] = '+';
        ElBase64.encodeMatrix[n++] = '/';
        ElBase64.decodeMatrix = new byte[128];
        for (int i = 0; i < ElBase64.decodeMatrix.length; ++i) {
            ElBase64.decodeMatrix[i] = -1;
        }
        for (int j = 0; j < 64; ++j) {
            ElBase64.decodeMatrix[ElBase64.encodeMatrix[j]] = (byte)j;
        }
    }
}
