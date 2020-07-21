/*
 * Copyright (c) 1996, 2019, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Oracle designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
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

package sun.security.util;

import java.io.InputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.util.Arrays;
import java.util.Date;
import java.util.Iterator;
import java.util.Vector;

import static java.nio.charset.StandardCharsets.*;

/**
 * A DER input stream, used for parsing ASN.1 DER-encoded data such as
 * that found in X.509 certificates.  DER is a subset of BER/1, which has
 * the advantage that it allows only a single encoding of primitive data.
 * (High level data such as dates still support many encodings.)  That is,
 * it uses the "Definite" Encoding Rules (DER) not the "Basic" ones (BER).
 *
 * <P>Note that, like BER/1, DER streams are streams of explicitly
 * tagged data values.  Accordingly, this programming interface does
 * not expose any variant of the java.io.InputStream interface, since
 * that kind of input stream holds untagged data values and using that
 * I/O model could prevent correct parsing of the DER data.
 *
 * <P>At this time, this class supports only a subset of the types of DER
 * data encodings which are defined.  That subset is sufficient for parsing
 * most X.509 certificates.
 *
 *
 * @author David Brownell
 * @author Amit Kapoor
 * @author Hemma Prafullchandra
 */

public class DerInputStream implements Iterable<DerValue> {

    final byte[] data;
    final int start;
    final int end;
    final boolean allowBER;
    int pos;

    @Override
    public Iterator<DerValue> iterator() {
        return new Iterator<DerValue>() {
            @Override
            public boolean hasNext() {
                return pos < end;
            }

            @Override
            public DerValue next() {
                try {
                    DerValue n = new DerValue(data, pos, end, allowBER, false);
                    pos = n.end;
                    return n;
                } catch (IOException ioe) {
                    throw new UncheckedIOException(ioe);
                }
            }
        };
    }

    public DerInputStream(byte[] data, int start, int length, boolean allowBER) {
        this.data = data;
        this.start = start;
        this.end = start + length;
        this.allowBER = allowBER;
        this.pos = start;
    }

    public DerInputStream(DerValue v) {
        this(v.buffer, v.start, v.end - v.start, v.allowBER);
    }

    public DerInputStream(byte[] data) throws IOException {
        this(data, 0, data.length, true);
    }

    public DerInputStream(byte[] data, int offset, int len) throws IOException {
        this(data, offset, len, true);
    }

    public byte[] toByteArray() {
        return Arrays.copyOfRange(data, start, end);
    }

    public int getInteger() throws IOException {
        return getDerValue().getInteger();
    }

    public BigInteger getBigInteger() throws IOException {
        return getDerValue().getBigInteger();
    }

    public BigInteger getPositiveBigInteger() throws IOException {
        return getDerValue().getPositiveBigInteger();
    }

    public int getEnumerated() throws IOException {
        return getDerValue().getEnumerated();
    }

    public byte[] getBitString() throws IOException {
        return getDerValue().getBitString();
    }

    public BitArray getUnalignedBitString() throws IOException {
        return getDerValue().getUnalignedBitString();
    }

    public byte[] getOctetString() throws IOException {
        return getDerValue().getOctetString();
    }

    public void getNull() throws IOException {
        getDerValue().getNull();
    }

    public ObjectIdentifier getOID() throws IOException {
        return getDerValue().getOID();
    }

    public DerValue[] getSequence(int startLen) throws IOException {
        return getDerValue().subs(DerValue.tag_Sequence);
    }

    public DerValue[] getSet(int startLen) throws IOException {
        return getDerValue().subs(DerValue.tag_Set);
    }

    public DerValue[] getSet(int startLen, boolean implicit) throws IOException {
        return getDerValue().subs((byte)0);
    }

    public DerValue getDerValue() throws IOException {
        DerValue result = new DerValue(
                this.data, this.pos, this.end - this.pos, this.allowBER, false);
        this.pos = result.end;
        return result;
    }

    public String getUTF8String() throws IOException {
        return getDerValue().getUTF8String();
    }

    public String getPrintableString() throws IOException {
        return getDerValue().getPrintableString();
    }

    public String getT61String() throws IOException {
        return getDerValue().getT61String();
    }

    public String getBMPString() throws IOException {
        return getDerValue().getBMPString();
    }

    public String getIA5String() throws IOException {
        return getDerValue().getIA5String();
    }

    public String getGeneralString() throws IOException {
        return getDerValue().getGeneralString();
    }

    public Date getUTCTime() throws IOException {
        return getDerValue().getUTCTime();
    }

    public Date getGeneralizedTime() throws IOException {
        return getDerValue().getGeneralizedTime();
    }

    public int peekByte() throws IOException {
        if (pos == end) {
            throw new IOException("At end");
        }
        return data[pos];
    }

    static int getLength(InputStream in) throws IOException {
        return getLength(in.read(), in);
    }

    /*
     * Get a length from the input stream, allowing for at most 32 bits of
     * encoding to be used.  (Not the same as getting a tagged integer!)
     *
     * @return the length or -1 if indefinite length found.
     * @exception IOException on parsing error or unsupported lengths.
     */
    static int getLength(int lenByte, InputStream in) throws IOException {
        int value, tmp;
        if (lenByte == -1) {
            throw new IOException("Short read of DER length");
        }

        String mdName = "DerInputStream.getLength(): ";
        tmp = lenByte;
        if ((tmp & 0x080) == 0x00) { // short form, 1 byte datum
            value = tmp;
        } else {                     // long form or indefinite
            tmp &= 0x07f;

            /*
             * NOTE:  tmp == 0 indicates indefinite length encoded data.
             * tmp > 4 indicates more than 4Gb of data.
             */
            if (tmp == 0)
                return -1;
            if (tmp < 0 || tmp > 4)
                throw new IOException(mdName + "lengthTag=" + tmp + ", "
                    + ((tmp < 0) ? "incorrect DER encoding." : "too big."));

            value = 0x0ff & in.read();
            tmp--;
            if (value == 0) {
                // DER requires length value be encoded in minimum number of bytes
                throw new IOException(mdName + "Redundant length bytes found");
            }
            while (tmp-- > 0) {
                value <<= 8;
                value += 0x0ff & in.read();
            }
            if (value < 0) {
                throw new IOException(mdName + "Invalid length bytes");
            } else if (value <= 127) {
                throw new IOException(mdName + "Should use short form for length");
            }
        }
        return value;
    }

    /*
     * Get a length from the input stream.
     *
     * @return the length
     * @exception IOException on parsing error or if indefinite length found.
     */
    static int getDefiniteLength(InputStream in) throws IOException {
        int len = getLength(in);
        if (len < 0) {
            throw new IOException("Indefinite length encoding not supported");
        }
        return len;
    }

    /**
     * Return to the position of the last <code>mark</code>
     * call.  A mark is implicitly set at the beginning of
     * the stream when it is created.
     */
    public void reset() { pos = start; }
    public void mark(int dummy) { }


    /**
     * Returns the number of bytes available for reading.
     * This is most useful for testing whether the stream is
     * empty.
     */
    public int available() { return end - pos; }
}
