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
 */
public class PemCertKeyTest {


    @Test
    public void testCertOnly() throws Exception {
        InputStream in = new FileInputStream("src/test/resources/pem/cert.pem");
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

    @Test
    public void testKeyOnly() throws Exception {
        InputStream in = new FileInputStream("src/test/resources/pem/key.pem");
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


    @Test
    public void testCertKey() throws Exception {
        InputStream in = MultiFileConcatSource.fromFiles(
                "src/test/resources/pem/certchain.pem",
                "src/test/resources/pem/key.pem"
        ).build();
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