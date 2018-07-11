package io.r2.wowzaletsencrypt;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.List;

/**
 * Parses a stream of PEM encoded X.509 chunks
 *
 * Imported from https://github.com/robymus/simple-pem-keystore
 */
public class PemStreamParser {

    protected InputStream in;

    public enum ChunkType { certificate, pkcs8_key, pkcs1_key };

    public PemStreamParser(InputStream in) {
        this.in = in;
    }

    /**
     * Parses input stream, looks for certificate and key chunks and sends them to the consumer
     *
     * @param consumer receives all chunks with type and the chunk content as list of lines
     *                 the list of lines include the chunk header and footer as well
     * @throws IOException on input errors
     * @throws CertificateException if parsing fails
     * @throws NoSuchAlgorithmException in case of cryptographic algorithm problems
     */
    public void parse(ChunkConsumer consumer) throws IOException, CertificateException, NoSuchAlgorithmException {
        List<String> chunk = new ArrayList<>();
        boolean inChunk = false;
        String chunkEndMarker = null;
        ChunkType currentChunkType = null;

        try (BufferedReader r = new BufferedReader(new InputStreamReader(in))) {
            String line;
            while ( (line = r.readLine()) != null) {
                line = line.trim(); // just to be sure
                if (line.length() == 0) continue; // ignore empty lines

                // inside chunk
                if (inChunk) {
                    // check for end of chunk
                    if (line.equals(chunkEndMarker)) {
                        chunk.add(line);
                        consumer.accept(currentChunkType, chunk);
                        chunk.clear();
                        inChunk = false;
                    }
                    else {
                        chunk.add(line);
                    }
                }
                // start of chunk
                else {
                    switch (line) {
                        case "-----BEGIN CERTIFICATE-----":
                            chunk.add(line);
                            currentChunkType = ChunkType.certificate;
                            inChunk = true;
                            chunkEndMarker = "-----END CERTIFICATE-----";
                            break;
                        case "-----BEGIN PRIVATE KEY-----":
                            chunk.add(line);
                            currentChunkType = ChunkType.pkcs8_key;
                            inChunk = true;
                            chunkEndMarker = "-----END PRIVATE KEY-----";
                            break;
                        case "-----BEGIN RSA PRIVATE KEY-----":
                            chunk.add(line);
                            currentChunkType = ChunkType.pkcs1_key;
                            inChunk = true;
                            chunkEndMarker = "-----END RSA PRIVATE KEY-----";
                            break;
                        default:
                            throw new CertificateException("Invalid chunk in input");
                    }
                }
            }
        }

        if (inChunk) {
            throw new CertificateException("Final chunk not closed");
        }
    }

    /**
     * Shorthand notation for parsing input stream
     *
     * @param in the input to parse
     * @param consumer receives all chunks with type and the chunk content as list of lines
     *                 the list of lines include the chunk header and footer as well
     * @throws IOException on input errors
     * @throws CertificateException if parsing fails
     * @throws NoSuchAlgorithmException in case of cryptographic algorithm problems
     *
     * @see PemStreamParser#parse(ChunkConsumer)
     */
    public static void parse(InputStream in, ChunkConsumer consumer) throws IOException, CertificateException, NoSuchAlgorithmException {
        new PemStreamParser(in).parse(consumer);
    }


    /**
     * Consumer to be called for each chunk
     */
    @FunctionalInterface
    public interface ChunkConsumer {
        void accept(ChunkType chunkType, List<String> chunk) throws CertificateException, NoSuchAlgorithmException;
    }
}
