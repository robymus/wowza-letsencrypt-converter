package io.r2.wowzaletsencrypt;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

/**
 * A certificate chain and private key read from PEM
 *
 * Imported from https://github.com/robymus/simple-pem-keystore
 */
public class PemCertKey {

    protected Date creationDate;
    protected Key privateKey;
    protected List<Certificate> certificateChain;
    protected Certificate[] certificateChainPacked;

    /**
     * Reads a new certificate chain and key from an input stream
     * Parses input to get key and certificates.
     * CreationDate is set to today
     *
     * @param input the input stream
     * @throws IOException in case if input error
     * @throws CertificateException if loading is failed
     * @throws NoSuchAlgorithmException if algorithms not available (now only RSA is used)
     */
    public PemCertKey(InputStream input) throws IOException, CertificateException, NoSuchAlgorithmException {
        this(input, new Date());
    }

    /**
     * Reads a new certificate chain and key from an input stream
     * Parses input to get key and certificates.
     * Creation Data is set to the specified time (millis from epoch)
     *
     * @param input the input stream
     * @param creationDate the creation date of this entry (for file based certificates, the file modification time)
     * @throws IOException in case if input error
     * @throws CertificateException if loading is failed
     * @throws NoSuchAlgorithmException if algorithms not available (now only RSA is used)
     */
    public PemCertKey(InputStream input, Date creationDate) throws IOException, CertificateException, NoSuchAlgorithmException {
        this.creationDate = creationDate;
        privateKey = null;
        certificateChain = new ArrayList<>();

        PemStreamParser.parse(input, (type, chunk) -> {
            switch (type) {
                case certificate:
                    addCertificate(chunk);
                    break;
                case pkcs8_key:
                case pkcs1_key:
                    setPrivateKey(chunk, type);
                    break;
            }
        });

        // put to packed structure
        certificateChainPacked = certificateChain.toArray(new Certificate[certificateChain.size()]);
    }

    /**
     * Internal method used during parsing : sets the private key in this entry
     *
     * @param key the chunk containing certificate
     * @param chunkType pkcs8_key or rsa_key - other values throw NoSuchAlgorithmException
     * @throws CertificateException if key already exists
     */
    private void setPrivateKey(List<String> key, PemStreamParser.ChunkType chunkType) throws CertificateException, NoSuchAlgorithmException {
        if (privateKey != null) throw new CertificateException("More than one private key in PEM input");

        String b64key = key.subList(1, key.size()-1).stream().collect(Collectors.joining());
        byte[] binKey = Base64.getDecoder().decode(b64key);

        KeySpec keySpec;

        switch (chunkType) {
            case pkcs8_key:
                keySpec = new PKCS8EncodedKeySpec(binKey);
                break;
            case pkcs1_key:
                keySpec = new PKCS8EncodedKeySpec(PKCS1Converter.toPKCS8(binKey));
                break;
            default:
                // this should not happen, as it is called only for matching types
                throw new NoSuchAlgorithmException("Invalid private key type: "+chunkType);
        }

        KeyFactory kf = KeyFactory.getInstance("RSA");
        try {
            privateKey = kf.generatePrivate(keySpec);
        }
        catch (InvalidKeySpecException e) {
            throw new NoSuchAlgorithmException(e);
        }

    }

    /**
     * Add a new certificate to the chain
     * @param chunk the chunk containing certificate
     */
    private void addCertificate(List<String> chunk) throws CertificateException {
        InputStream is = new ByteArrayInputStream(
                chunk.stream().collect(Collectors.joining("\n")).getBytes(StandardCharsets.UTF_8)
        );
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        certificateChain.add(cf.generateCertificate(is));
    }

    /**
     * Creation date is unknown in this store, so return object creation date
     * @return creation date
     */
    public Date getCreationDate() {
        return creationDate;
    }

    /**
     * Gets the private key - private keys are not password protected
     *
     * @return the private key
     * @throws UnrecoverableKeyException if password is incorrect
     */
    public Key getPrivateKey() throws UnrecoverableKeyException {
        return privateKey;
    }

    /**
     * @return certificate chain
     */
    public Certificate[] getCertificateChain() {
        return certificateChainPacked;
    }

    /**
     * @return the certificate or null if not found in input
     */
    public Certificate getCertificate() {
        return certificateChainPacked.length > 0 ? certificateChainPacked[0] : null;
    }

    /**
     * @return true if input has a key
     */
    public boolean hasKey() {
        return privateKey != null;
    }

    /**
     * @return true if input has a certificate
     */
    public boolean hasCertificate() {
        return certificateChainPacked.length > 0;
    }

    /**
     * @return true if parameter certificate matches this one
     */
    public boolean matchesCertificate(Certificate other) {
        if (certificateChainPacked.length == 0) return false;
        return certificateChainPacked[0].equals(other);
    }

}
