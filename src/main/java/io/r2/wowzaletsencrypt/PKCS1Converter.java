package io.r2.wowzaletsencrypt;

import java.math.BigInteger;
import java.util.Base64;

/**
 * PKCS1Converter - helper class to convert PKCS#1 keys (--BEGIN RSA PRIVATE KEY--) to PKCS#8 format
 * Based on the magical code at https://stackoverflow.com/a/33594033
 *
 * @author robymus <r@r2.io>
 */
public class PKCS1Converter {

    /**
     * Create a pkcs#8 binary header for a a pkcs#1 binary key
     *
     * @param innerKey
     * @return
     */
    public static byte[] toPKCS8(byte[] innerKey) {
        final byte[] result = new byte[innerKey.length + 26];
        System.arraycopy(Base64.getDecoder().decode("MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKY="), 0, result, 0, 26);
        System.arraycopy(BigInteger.valueOf(result.length - 4).toByteArray(), 0, result, 2, 2);
        System.arraycopy(BigInteger.valueOf(innerKey.length).toByteArray(), 0, result, 24, 2);
        System.arraycopy(innerKey, 0, result, 26, innerKey.length);
        return result;
    }
}
