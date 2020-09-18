/*
 * Copyright (c) 2020, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */
import org.testng.Assert;
import org.testng.annotations.Test;

import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.zip.DataFormatException;
import java.util.zip.Deflater;
import java.util.zip.Inflater;

import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * @test
 * @bug 8252739
 * @summary Verify Deflater.setDictionary(dictionary, offset, length) uses the offset
 * @run testng/othervm DeflaterDictionaryTests
 */
public class DeflaterDictionaryTests {
    private static final int RESULT_SIZE = 1024;
    private static final String message = "Welcome to US Open;"
            +"Welcome to US Open;"
            +"Welcome to US Open;"
            +"Welcome to US Open;"
            +"Welcome to US Open;"
            +"Welcome to US Open;";
    private static final String DICTIONARY = "US Open";

    /**
     * Validate that an offset can be used with Deflater::setDictionary
     * @throws Exception if an error occurs
     */
    @Test
    public void ByteArrayTest() throws Exception {
        System.out.println("Original Message length : " + message.length());
        byte[] input = message.getBytes(UTF_8);
        // Compress the bytes
        byte[] output = new byte[RESULT_SIZE];
        Deflater deflater = new Deflater();
        deflater.setDictionary(DICTIONARY.getBytes(UTF_8), 1, 3);
        deflater.setInput(input);
        deflater.finish();
        int compressedDataLength = deflater.deflate(output,0 , output.length, Deflater.NO_FLUSH);
        System.out.println("Total uncompressed bytes output :" + deflater.getTotalOut());
        System.out.println("Compressed Message Checksum :" + deflater.getAdler());
        deflater.finished();
        System.out.println("Compressed Message length : " + compressedDataLength);

        // Decompress the bytes
        Inflater inflater = new Inflater();
        inflater.setInput(output, 0, compressedDataLength);
        byte[] result = new byte[RESULT_SIZE];
        int resultLength = inflater.inflate(result);
        if(inflater.needsDictionary()) {
            System.out.println("Specifying Dictionary");
            inflater.setDictionary(DICTIONARY.getBytes(UTF_8), 1, 3);
            resultLength = inflater.inflate(result);
        } else {
            System.out.println("Did not need to use a Dictionary");
        }
        inflater.finished();

        // Decode the bytes into a String
        String resultMessage = new String(result, 0, resultLength, UTF_8);
        System.out.println("UnCompressed Message Checksum :" + inflater.getAdler());
        System.out.println("UnCompressed Message length : " + resultMessage.length());

        Assert.assertEquals(message.length(), resultLength);
        Assert.assertEquals(input, Arrays.copyOf(result, resultLength));

        // Release Resources
        deflater.end();
        inflater.end();
    }

    /**
     * Validate that a ByteBuffer can be used with Deflater::setDictionary
     * @throws Exception if an error occurs
     */
    @Test
    public void testByteBufferWrap() throws DataFormatException {

        System.out.println("Original Message length : " + message.length());
        byte[] input = message.getBytes(UTF_8);

        // Compress the bytes
        byte[] output = new byte[RESULT_SIZE];
        ByteBuffer dictDef = ByteBuffer.wrap(DICTIONARY.getBytes(UTF_8));
        ByteBuffer dictInf = ByteBuffer.wrap(DICTIONARY.getBytes(UTF_8));
        Deflater deflater = new Deflater();
        deflater.setDictionary(dictDef);
        deflater.setInput(input);
        deflater.finish();
        int compressedDataLength = deflater.deflate(output,0 , output.length, Deflater.NO_FLUSH);
        System.out.println("Total uncompressed bytes output :" + deflater.getTotalOut());
        System.out.println("Compressed Message Checksum :" + deflater.getAdler());
        deflater.finished();
        System.out.println("Compressed Message length : " + compressedDataLength);

        // Decompress the bytes
        Inflater inflater = new Inflater();
        inflater.setInput(output, 0, compressedDataLength);
        byte[] result = new byte[RESULT_SIZE];
        int resultLength = inflater.inflate(result);
        if(inflater.needsDictionary()) {
            System.out.println("Specifying Dictionary");
            inflater.setDictionary(dictInf);
            resultLength = inflater.inflate(result);
        } else {
            System.out.println("Did not need to use a Dictionary");
        }
        inflater.finished();

        // Decode the bytes into a String
        String resultMessage = new String(result, 0, resultLength, UTF_8);
        System.out.println("UnCompressed Message Checksum :" + inflater.getAdler());
        System.out.println("UnCompressed Message length : " + resultMessage.length());

        Assert.assertEquals(message.length(), resultLength);
        Assert.assertEquals(input, Arrays.copyOf(result, resultLength));

        // Release Resources
        deflater.end();
        inflater.end();
    }

    /**
     * Validate that ByteBuffer::allocateDirect can be used with Deflater::setDictionary
     * @throws Exception if an error occurs
     */
    @Test
    public void testByteBufferDirect() throws Exception {
        System.out.println("Original Message length : " + message.length());
        byte[] input = message.getBytes(UTF_8);
        // Compress the bytes
        byte[] output = new byte[RESULT_SIZE];
        ByteBuffer dictDef = ByteBuffer.allocateDirect(DICTIONARY.length());
        ByteBuffer dictInf = ByteBuffer.allocateDirect(DICTIONARY.length());
        Deflater deflater = new Deflater();
        deflater.setDictionary(dictDef);
        deflater.setInput(input);
        deflater.finish();
        int compressedDataLength = deflater.deflate(output,0 , output.length, Deflater.NO_FLUSH);
        System.out.println("Total uncompressed bytes output :" + deflater.getTotalOut());
        System.out.println("Compressed Message Checksum :" + deflater.getAdler());
        deflater.finished();
        System.out.println("Compressed Message length : " + compressedDataLength);

        // Decompress the bytes
        Inflater inflater = new Inflater();
        inflater.setInput(output, 0, compressedDataLength);
        byte[] result = new byte[RESULT_SIZE];
        int resultLength = inflater.inflate(result);
        if(inflater.needsDictionary()){
            System.out.println("Specifying Dictionary");
            inflater.setDictionary(dictInf);
            resultLength = inflater.inflate(result);
        } else {
            System.out.println("Did not need to use a Dictionary");
        }
        inflater.finished();

        // Decode the bytes into a String
        String resultMessage = new String(result, 0, resultLength, UTF_8);
        System.out.println("UnCompressed Message Checksum :" + inflater.getAdler());
        System.out.println("UnCompressed Message length : " + resultMessage.length());

        Assert.assertEquals(message.length(), resultLength);
        Assert.assertEquals(input, Arrays.copyOf(result, resultLength));

        // Release Resources
        deflater.end();
        inflater.end();
    }
}
