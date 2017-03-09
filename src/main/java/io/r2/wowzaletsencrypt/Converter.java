package io.r2.wowzaletsencrypt;

import java.io.*;
import java.nio.file.*;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.stream.Stream;

/**
 * Main class of the converter
 *
 * Command line usage:
 *      [-v] <output-path> [<letsencrypt-live-path>]
 *
 */
public class Converter {

    protected boolean verbose = false;
    protected Path inputPath;
    protected Path outputPath;

    /** Certificate ID -> certificate map */
    protected HashMap<String, PemCertKey> certificates;
    /** Domain name -> certificate ID map (use linked map to keep ordering) */
    protected LinkedHashMap<String, String> domains;

    public Converter(String inputPath, String outputPath) {
        this.inputPath = Paths.get(inputPath);
        this.outputPath = Paths.get(outputPath);

        certificates = new HashMap<>();
        domains = new LinkedHashMap<>();
    }

    public void setVerbose(boolean v) {
        verbose = v;
    }

    /**
     * Reads all certificates to memory, parses and checks them
     * @return true if reading was successful
     */
    public boolean readCertificates() {
        String status = "initialization";

        try {
            // iterate through directory of certificates
            try (DirectoryStream<Path> dirList = Files.newDirectoryStream(inputPath)) {
                for (Path dir : dirList) {
                    if (!dir.toFile().isDirectory()) continue;
                    String certID = dir.getFileName().toString();
                    status = certID;
                    if (verbose) System.out.println("Reading "+certID);

                    // read certificate
                    InputStream in = MultiFileConcatSource.fromFiles(
                            dir.resolve("fullchain.pem"),
                            dir.resolve("privkey.pem")
                    ).build();
                    PemCertKey pem = new PemCertKey(in);

                    certificates.put(certID, pem);

                    // parse list of domains from subject alternative names extension (DNSName)
                    Certificate cert = pem.getCertificate();
                    if (!(cert instanceof X509Certificate)) {
                        System.err.println(certID+": can't parse as X.509 certificate");
                        return false;
                    }
                    X509Certificate x509 = (X509Certificate) cert;

                    Stream<String> dnsNames = x509.getSubjectAlternativeNames().stream().filter(ext ->
                        ext.size() == 2 &&
                        ext.get(0) instanceof Integer && ((Integer) ext.get(0)).intValue() == 2 &&
                        ext.get(1) instanceof String
                    ).map(ext -> (String)ext.get(1));

                    ArrayList<String> domainList = new ArrayList<String>();
                    dnsNames.forEach(value-> {
                        if (verbose) System.out.println("-> "+value);
                        domainList.add(value);
                    });

                    // check if parsed successfully
                    if (domainList.size() == 0) {
                        System.err.println(certID+": no DNSName subject name extensions found");
                        return false;
                    }

                    // add to domain map
                    domainList.forEach(d -> domains.put(d, certID));
                }
            }

            // all done
            return true;
        }
        catch (IOException | CertificateException | NoSuchAlgorithmException e) {
            System.err.println("Read error in "+status+":"+e.getMessage());
            return false;
        }
    }

    /**
     * Writes certificates in JKS format
     * @return true if writing was successful
     */
    public boolean writeJKS() {
        // hardcoded password
        String password = "secret";
        char[] passwordChr = password.toCharArray();
        // hardcoded alias for Wowza Streaming Engine
        String alias = "server";
        // name of output map file
        String mapName = "jksmap.txt";

        String status = "initialization";
        try {
            // write all certificates to JKS
            for (Map.Entry<String, PemCertKey> e : certificates.entrySet()) {
                String certID = e.getKey();
                PemCertKey cert = e.getValue();
                String jksName = certID+".jks";
                status = certID;

                if (verbose) System.out.println("Writing "+jksName);

                // create empty keystore in memory
                KeyStore ks = KeyStore.getInstance("JKS");
                ks.load(null, passwordChr);

                // add certificate/key
                ks.setKeyEntry(alias, cert.getPrivateKey(), passwordChr, cert.getCertificateChain());

                // write to file
                try(FileOutputStream f = new FileOutputStream(outputPath.resolve(jksName).toFile())) {
                    ks.store(f, passwordChr);
                }
            }

            if (verbose) System.out.println("Writing "+mapName);

            // write to .tmp file and rename atomically
            Path tmpMap = outputPath.resolve(mapName+".tmp");
            Path realMap = outputPath.resolve(mapName);

            // write domain map to jksmap.txt
            try(PrintWriter f = new PrintWriter(tmpMap.toFile())) {
                domains.forEach((domain, certID)->
                    f.printf("%s={\"keyStorePath\":\"%s\", \"keyStorePassword\":\"%s\", \"keyStoreType\":\"JKS\"}\n",
                                jsonEscape(domain),
                                jsonEscape(outputPath.resolve(certID+".jks").toAbsolutePath().toString()),
                                jsonEscape(password)
                            )
                );
            }

            // rename
            Files.move(tmpMap, realMap, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        }
        catch (IOException | KeyStoreException | CertificateException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
            System.err.println("Write error in "+status+":"+e.getMessage());
            return false;
        }
        return true;
    }

    /**
     * Minimal JSON escaping for output
     * Escapes only \ and ", as other special characters are not likely in domain or path,
     * and also should not be in passwords
     */
    protected String jsonEscape(String s) {
        return s.replaceAll("[\"\\\\]", "\\\\$0");
    }

    public static void main(String[] args) {
        // parse arguments
        boolean verbose = false;
        String outputPath;
        String inputPath = "/etc/letsencrypt/live";

        int idx = 0;
        if (idx < args.length && args[idx].equals("-v")) {
            verbose = true;
            idx++;
        }

        if (idx >= args.length) {
            System.err.println("Required argument missing. Usage: [-v] <output-path> [<letsencrypt-live-path>]");
            System.exit(1);
        }

        outputPath = args[idx++];
        if (idx < args.length) inputPath = args[idx++];
        // extra arguments are ignored

        if (verbose) {
            System.out.println("Converting certificates: "+inputPath+" => "+outputPath);
        }

        Converter c = new Converter(inputPath, outputPath);
        c.setVerbose(verbose);

        if (!c.readCertificates()) {
            System.err.println("Error reading certificates, aborting without writing anything");
            System.exit(2);
        }

        if (!c.writeJKS()) {
            System.err.println("Error writing output, aborting. Note: partial changes might be written already!");
            System.exit(3);
        }

        // terminate normally
        System.exit(0);
    }


}
