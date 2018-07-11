package io.r2.wowzaletsencrypt;

import io.r2.wowzaletsencrypt.MultiFileConcatSource;
import org.testng.annotations.Test;

import java.io.FileInputStream;
import java.io.InputStream;
import java.security.cert.Certificate;
import java.util.Date;

import static org.assertj.core.api.Assertions.*;

/**
 * Tests PemCertKey
 * Imported from https://github.com/robymus/simple-pem-keystore
 * Added extra tests for trailing new lines
 */
public class PemCertKeyTest {

    @Test
    public void testCert() throws Exception {
        doTestCert("src/test/resources/pem/cert.pem");
    }

    @Test
    public void testCertBlankLine() throws Exception {
        doTestCert("src/test/resources/pem/cert-with-trailing-blank-line.pem");
    }

    @Test
    public void testCertAcme() throws Exception {
        doTestCert("src/test/resources/pem/acme-cert.pem");
    }

    @Test
    public void testKey() throws Exception {
        doTestKey("src/test/resources/pem/key.pem");
    }

    @Test
    public void testKeyBlankLine() throws Exception {
        doTestKey("src/test/resources/pem/key-with-two-trailing-blank-lines.pem");
    }

    @Test
    public void testKeyAcme() throws Exception {
        doTestKey("src/test/resources/pem/acme-key.pem");
    }


    @Test
    public void testCertKey() throws Exception {
        doTestCertKey(
            "src/test/resources/pem/certchain.pem",
            "src/test/resources/pem/key.pem"
        );
    }

    @Test
    public void testCertKeyBlankLine() throws Exception {
        doTestCertKey(
                "src/test/resources/pem/certchain-with-trailing-blank-line.pem",
                "src/test/resources/pem/key-with-two-trailing-blank-lines.pem"
        );
    }

    @Test
    public void testCertKeyAcme() throws Exception {
        doTestCertKey(
                "src/test/resources/pem/acme-fullchain.pem",
                "src/test/resources/pem/acme-key.pem"
        );
    }

    public void doTestCert(String fn) throws Exception {
        InputStream in = new FileInputStream(fn);
        PemCertKey t = new PemCertKey(in);

        Certificate cert = t.getCertificate();
        assertThat(cert).isNotNull();
        assertThat(cert.getType()).isEqualTo("X.509");

        assertThat(t.hasCertificate()).isTrue();
        assertThat(t.getCertificateChain()).hasSize(1);
        assertThat(t.getCertificateChain()[0]).isEqualTo(cert);

        assertThat(t.matchesCertificate(cert)).isTrue();
        assertThat(t.matchesCertificate(null)).isFalse();

        assertThat(t.hasKey()).isFalse();
        assertThat(t.getPrivateKey()).isNull();

        assertThat(t.getCreationDate()).isCloseTo(new Date(), 5000);
    }

    public void doTestKey(String fn) throws Exception {
        InputStream in = new FileInputStream(fn);
        PemCertKey t = new PemCertKey(in);

        assertThat(t.hasCertificate()).isFalse();
        assertThat(t.getCertificateChain()).hasSize(0);
        assertThat(t.getCertificate()).isNull();

        assertThat(t.matchesCertificate(null)).isFalse();

        assertThat(t.hasKey()).isTrue();
        assertThat(t.getPrivateKey().getFormat()).isEqualTo("PKCS#8");
        assertThat(t.getPrivateKey().getAlgorithm()).isEqualTo("RSA");

        assertThat(t.getCreationDate()).isCloseTo(new Date(), 5000);
    }


    public void doTestCertKey(String fn_cert, String fn_key) throws Exception {
        InputStream in = MultiFileConcatSource.fromFiles(fn_cert, fn_key).build();
        PemCertKey t = new PemCertKey(in);

        Certificate cert = t.getCertificate();
        assertThat(cert).isNotNull();
        assertThat(cert.getType()).isEqualTo("X.509");

        assertThat(t.hasCertificate()).isTrue();
        assertThat(t.getCertificateChain()).hasSize(2);
        assertThat(t.getCertificateChain()[0]).isEqualTo(cert);

        assertThat(t.matchesCertificate(cert)).isTrue();
        assertThat(t.matchesCertificate(t.getCertificateChain()[1])).isFalse();
        assertThat(t.matchesCertificate(null)).isFalse();

        assertThat(t.hasKey()).isTrue();
        assertThat(t.getPrivateKey().getFormat()).isEqualTo("PKCS#8");
        assertThat(t.getPrivateKey().getAlgorithm()).isEqualTo("RSA");

        assertThat(t.getCreationDate()).isCloseTo(new Date(), 5000);
    }

}