package io.r2.wowzaletsencrypt;

import java.io.*;
import java.nio.file.Path;

/**
 * MultiFileConcatSource - builds an InputStream from the pre-buffered contents of multiple files
 * This builder class is mutable, it builds into an internal buffer
 *
 * Imported from https://github.com/robymus/simple-pem-keystore
 */
public class MultiFileConcatSource  {

    protected ByteArrayOutputStream contents;

    /**
     * Create an empty builder
     */
    public MultiFileConcatSource() {
        contents = new ByteArrayOutputStream();
    }

    /**
     * Append the contents of an input stream to this source
     *
     * @param is the source input stream
     * @return the object itself for chaining
     * @throws IOException in case of error
     */
    public MultiFileConcatSource add(InputStream is) throws IOException {
        byte[] buffer = new byte[2048];
        int read;
        while ( (read = is.read(buffer)) > 0) {
            contents.write(buffer, 0, read);
        }
        return this;
    }

    /**
     * Append the contents of a file to this source
     * @param file reference to the input file
     * @return the object itself for chaining
     * @throws IOException in case of error
     */
    public MultiFileConcatSource add(File file) throws IOException {
        try (InputStream is = new FileInputStream(file)) {
            return add(is);
        }
    }


    /**
     * Append the contents of a file to this source
     * @param fileName the path of the input file
     * @return the object itself for chaining
     * @throws IOException in case of error
     */
    public MultiFileConcatSource add(Path fileName) throws IOException {
        return add(fileName.toFile());
    }

    /**
     * Append the contents of a file to this source
     * @param fileName the path of the input file
     * @return the object itself for chaining
     * @throws IOException in case of error
     */
    public MultiFileConcatSource add(String fileName) throws IOException {
        try (InputStream is = new FileInputStream(fileName)) {
            return add(is);
        }
    }

    /**
     * Gets the current size of the building buffer
     *
     * @return size of building buffer
     */
    public int size() {
        return contents.size();
    }

    /**
     * Builds an input stream from the currently accumulated contents
     *
     * @return a ByteArrayInputStream created from the added contents
     */
    public ByteArrayInputStream build() {
        return new ByteArrayInputStream(contents.toByteArray());
    }

    /**
     * Creates an empty source (files may be added later)
     *
     * @return an empty (but extendable) builder
     */
    public static MultiFileConcatSource empty() {
        return new MultiFileConcatSource();
    }

    /**
     * Creates a new builder from multiple files
     *
     * @param paths list of filenames as File
     * @return the prepared builder
     * @throws IOException in case of error
     */
    public static MultiFileConcatSource fromFiles(File... paths) throws IOException {
        MultiFileConcatSource b = new MultiFileConcatSource();
        for (File f : paths) b.add(f);
        return b;
    }

    /**
     * Creates a new builder from multiple files
     *
     * @param paths list of filenames as Path
     * @return the prepared builder
     * @throws IOException in case of error
     */
    public static MultiFileConcatSource fromFiles(Path... paths) throws IOException {
        MultiFileConcatSource b = new MultiFileConcatSource();
        for (Path p : paths) b.add(p);
        return b;
    }

    /**
     * Creates a new builder from multiple files
     *
     * @param paths list of filenames as String
     * @return the prepared builder
     * @throws IOException in case of error
     */
    public static MultiFileConcatSource fromFiles(String... paths) throws IOException {
        MultiFileConcatSource b = new MultiFileConcatSource();
        for (String s : paths) b.add(s);
        return b;
    }

}
