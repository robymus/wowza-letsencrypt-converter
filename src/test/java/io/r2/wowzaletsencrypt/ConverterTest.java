package io.r2.wowzaletsencrypt;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.testng.annotations.AfterTest;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.Test;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.*;

/**
 * End to end test on the test files
 */
public class ConverterTest {

    Path outDir;

    @BeforeTest
    public void setUp() throws Exception {
        outDir = Files.createTempDirectory("wlconvert");
    }

    @AfterTest
    public void tearDown() throws Exception {
        // delete temporary out directory recursively
        Files.walk(outDir)
                .sorted(Comparator.reverseOrder())
                .map(Path::toFile)
                .forEach(File::delete);
    }

    private void checkLine(List<String> mapLines, String domain) throws Exception {
        // find the line containing domain
        String prefix = domain+"=";
        Optional<String> line0 = mapLines.stream().filter(s -> s.startsWith(prefix)).findAny();
        assertThat(line0).isNotEmpty();
        String json = line0.get().substring(prefix.length());

        ObjectMapper mapper = new ObjectMapper();
        JsonData data = mapper.readValue(new ByteArrayInputStream(json.getBytes(StandardCharsets.UTF_8)), JsonData.class);
        assertThat(data).isNotNull();
        assertThat(data.keyStorePassword).isEqualTo("secret");
        assertThat(data.keyStoreType).isEqualTo("JKS");

        Path p = Paths.get(data.keyStorePath);
        assertThat(p).isRegularFile();

        // read keystore
        KeyStore ks = KeyStore.getInstance("JKS");
        ks.load(new FileInputStream(p.toFile()), "secret".toCharArray());

        // get certificate
        Certificate cert = ks.getCertificate("server");
        assertThat(cert).isInstanceOf(X509Certificate.class);

        X509Certificate x509 = (X509Certificate) cert;
        // look for DNS name matching domain
        Stream<String> dnsNames = x509.getSubjectAlternativeNames().stream().filter(ext ->
                ext.size() == 2 &&
                ext.get(0) instanceof Integer && ((Integer) ext.get(0)).intValue() == 2 &&
                ext.get(1) instanceof String
        ).map(ext -> (String)ext.get(1));

        assertThat(dnsNames).contains(domain);
    }

    private void checkResultsLetsEncrypt() throws Exception {
        // test map
        Path map = outDir.resolve("jksmap.txt");
        assertThat(map).isRegularFile();
        List<String> mapLines = Files.lines(map).collect(Collectors.toList());

        assertThat(mapLines.size()).isEqualTo(6);

        checkLine(mapLines, "multi-1.not-secure.r2.io");
        checkLine(mapLines, "multi-2.not-secure.r2.io");
        checkLine(mapLines, "multi-3.not-secure.r2.io");
        checkLine(mapLines, "not-secure.r2.io");
        checkLine(mapLines, "www.not-secure.r2.io");
        checkLine(mapLines, "single.not-secure.r2.io");
    }

    @Test
    public void testProcessLetsEncrypt() throws Exception {
        Converter c = new Converter(
                "src/test/resources/letsencrypt",
                outDir.toAbsolutePath().toString()
        );
        assertThat(c.readCertificates()).isTrue();
        assertThat(c.writeJKS()).isTrue();
        checkResultsLetsEncrypt();
    }

    private void checkResultsAcme() throws Exception {
        // test map
        Path map = outDir.resolve("jksmap.txt");
        assertThat(map).isRegularFile();
        List<String> mapLines = Files.lines(map).collect(Collectors.toList());

        assertThat(mapLines.size()).isEqualTo(1);

        checkLine(mapLines, "not-secure-acme.r2.io");
    }



    @Test
    public void testProcessAcme() throws Exception {
        Converter c = new Converter(
                "src/test/resources/acme.sh",
                outDir.toAbsolutePath().toString()
        );
        assertThat(c.readCertificates()).isTrue();
        assertThat(c.writeJKS()).isTrue();
        checkResultsAcme();
    }


    public static class JsonData {
        public String keyStorePath;
        public String keyStorePassword;
        public String keyStoreType;
    }

}