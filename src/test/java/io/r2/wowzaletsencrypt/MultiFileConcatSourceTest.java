package io.r2.wowzaletsencrypt;

import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;

import static org.assertj.core.api.Assertions.*;

/**
 * Imported from https://github.com/robymus/simple-pem-keystore
 */
public class MultiFileConcatSourceTest {

    String[] testStr = new String[] {
            "str1",
            "***str2***",
            "__3__"
    };

    Path[] testPath;

    byte[] result;

    @BeforeClass
    public void setUp() throws Exception {
        ByteArrayOutputStream o = new ByteArrayOutputStream();

        testPath = new Path[testStr.length];
        for (int i = 0; i < testStr.length; i++) {
            o.write(testStr[i].getBytes(StandardCharsets.UTF_8));
            testPath[i] = Files.createTempFile("test-temp-"+i, ".tmp");
            Files.write(testPath[i], testStr[i].getBytes(StandardCharsets.UTF_8));
        }

        result = o.toByteArray();
    }

    @AfterClass
    public void tearDown() throws Exception {
        for (Path p : testPath) {
            Files.delete(p);
        }
    }

    /** Creates an in-memory input stream from a test string */
    InputStream is(int i) {
        return new ByteArrayInputStream(testStr[i].getBytes(StandardCharsets.UTF_8));
    }

    void validate(MultiFileConcatSource s) throws Exception {
        byte[] res = new byte[1024];
        int len = s.build().read(res);
        res = Arrays.copyOfRange(res, 0, len);
        assertThat(res).containsExactly(result);
    }


    @Test
    public void testAdd_is() throws Exception {
        MultiFileConcatSource s = new MultiFileConcatSource();
        s.add(is(0)); s.add(is(1)); s.add(is(2));
        validate(s);
    }

    @Test
    public void testAdd_file() throws Exception {
        MultiFileConcatSource s = new MultiFileConcatSource();
        s.add(testPath[0].toFile());
        s.add(testPath[1].toFile());
        s.add(testPath[2].toFile());
        validate(s);
    }

    @Test
    public void testAdd_path() throws Exception {
        MultiFileConcatSource s = new MultiFileConcatSource();
        s.add(testPath[0]);
        s.add(testPath[1]);
        s.add(testPath[2]);
        validate(s);
    }

    @Test
    public void testAdd_fn() throws Exception {
        MultiFileConcatSource s = new MultiFileConcatSource();
        s.add(testPath[0].toFile().getCanonicalPath());
        s.add(testPath[1].toFile().getCanonicalPath());
        s.add(testPath[2].toFile().getCanonicalPath());
        validate(s);
    }

    @Test
    public void testSize() throws Exception {
        MultiFileConcatSource s = new MultiFileConcatSource();
        s.add(is(0)); s.add(is(1)); s.add(is(2));
        assertThat(s.size()).isEqualTo(result.length);
    }

    @Test
    public void testEmpty() throws Exception {
        assertThat(MultiFileConcatSource.empty().size()).isEqualTo(0);
    }

    @Test
    public void testFromFiles_file() throws Exception {
        validate(
                MultiFileConcatSource.fromFiles(
                        testPath[0].toFile(),
                        testPath[1].toFile(),
                        testPath[2].toFile()
                )
        );
    }

    @Test
    public void testFromFiles_path() throws Exception {
        validate(MultiFileConcatSource.fromFiles(testPath));
    }

    @Test
    public void testFromFiles_fn() throws Exception {
        validate(
                MultiFileConcatSource.fromFiles(
                        testPath[0].toFile().getCanonicalPath(),
                        testPath[1].toFile().getCanonicalPath(),
                        testPath[2].toFile().getCanonicalPath()
                )
        );
    }


}