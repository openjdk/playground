/**
 * Copyright (c) 1996, 2020, Oracle and/or its affiliates. All rights reserved.
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

import sun.util.calendar.CalendarDate;
import sun.util.calendar.CalendarSystem;

import java.io.*;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.nio.charset.IllegalCharsetNameException;
import java.nio.charset.UnsupportedCharsetException;
import java.util.*;

import static java.nio.charset.StandardCharsets.*;

/**
 * Represents a single DER-encoded value.  DER encoding rules are a subset
 * of the "Basic" Encoding Rules (BER), but they only support a single way
 * ("Definite" encoding) to encode any given value.
 *
 * <P>All DER-encoded data are triples <em>{type, length, data}</em>.  This
 * class represents such tagged values as they have been read (or constructed),
 * and provides structured access to the encoded data.
 *
 * <P>At this time, this class supports only a subset of the types of DER
 * data encodings which are defined.  That subset is sufficient for parsing
 * most X.509 certificates, and working with selected additional formats
 * (such as PKCS #10 certificate requests, and some kinds of PKCS #7 data).
 *
 * A note with respect to T61/Teletex strings: From RFC 1617, section 4.1.3
 * and RFC 5280, section 8, we assume that this kind of string will contain
 * ISO-8859-1 characters only.
 *
 *
 * @author David Brownell
 * @author Amit Kapoor
 * @author Hemma Prafullchandra
 */
public class DerValue {

    /** The tag class types */
    public static final byte TAG_UNIVERSAL = (byte)0x000;
    public static final byte TAG_APPLICATION = (byte)0x040;
    public static final byte TAG_CONTEXT = (byte)0x080;
    public static final byte TAG_PRIVATE = (byte)0x0c0;

    /*
     * The type starts at the first byte of the encoding, and
     * is one of these tag_* values.  That may be all the type
     * data that is needed.
     */

    /*
     * These tags are the "universal" tags ... they mean the same
     * in all contexts.  (Mask with 0x1f -- five bits.)
     */

    /** Tag value indicating an ASN.1 "BOOLEAN" value. */
    public static final byte    tag_Boolean = 0x01;

    /** Tag value indicating an ASN.1 "INTEGER" value. */
    public static final byte    tag_Integer = 0x02;

    /** Tag value indicating an ASN.1 "BIT STRING" value. */
    public static final byte    tag_BitString = 0x03;

    /** Tag value indicating an ASN.1 "OCTET STRING" value. */
    public static final byte    tag_OctetString = 0x04;

    /** Tag value indicating an ASN.1 "NULL" value. */
    public static final byte    tag_Null = 0x05;

    /** Tag value indicating an ASN.1 "OBJECT IDENTIFIER" value. */
    public static final byte    tag_ObjectId = 0x06;

    /** Tag value including an ASN.1 "ENUMERATED" value */
    public static final byte    tag_Enumerated = 0x0A;

    /** Tag value indicating an ASN.1 "UTF8String" value. */
    public static final byte    tag_UTF8String = 0x0C;

    /** Tag value including a "printable" string */
    public static final byte    tag_PrintableString = 0x13;

    /** Tag value including a "teletype" string */
    public static final byte    tag_T61String = 0x14;

    /** Tag value including an ASCII string */
    public static final byte    tag_IA5String = 0x16;

    /** Tag value indicating an ASN.1 "UTCTime" value. */
    public static final byte    tag_UtcTime = 0x17;

    /** Tag value indicating an ASN.1 "GeneralizedTime" value. */
    public static final byte    tag_GeneralizedTime = 0x18;

    /** Tag value indicating an ASN.1 "GenerallString" value. */
    public static final byte    tag_GeneralString = 0x1B;

    /** Tag value indicating an ASN.1 "UniversalString" value. */
    public static final byte    tag_UniversalString = 0x1C;

    /** Tag value indicating an ASN.1 "BMPString" value. */
    public static final byte    tag_BMPString = 0x1E;

    // CONSTRUCTED seq/set

    /**
     * Tag value indicating an ASN.1
     * "SEQUENCE" (zero to N elements, order is significant).
     */
    public static final byte    tag_Sequence = 0x30;

    /**
     * Tag value indicating an ASN.1
     * "SEQUENCE OF" (one to N elements, order is significant).
     */
    public static final byte    tag_SequenceOf = 0x30;

    /**
     * Tag value indicating an ASN.1
     * "SET" (zero to N members, order does not matter).
     */
    public static final byte    tag_Set = 0x31;

    /**
     * Tag value indicating an ASN.1
     * "SET OF" (one to N members, order does not matter).
     */
    public static final byte    tag_SetOf = 0x31;

    // Instance fields start here:
    public /*final*/ byte tag;
    final byte[] buffer;
    final int start;
    final int end;
    public final boolean allowBER;

    final public DerInputStream data;

    /*
     * These values are the high order bits for the other kinds of tags.
     */

    /**
     * Returns true if the tag class is UNIVERSAL.
     */
    public boolean isUniversal()      { return ((tag & 0x0c0) == 0x000); }

    /**
     * Returns true if the tag class is APPLICATION.
     */
    public boolean isApplication()    { return ((tag & 0x0c0) == 0x040); }

    /**
     * Returns true iff the CONTEXT SPECIFIC bit is set in the type tag.
     * This is associated with the ASN.1 "DEFINED BY" syntax.
     */
    public boolean isContextSpecific() { return ((tag & 0x0c0) == 0x080); }

    /**
     * Returns true iff the CONTEXT SPECIFIC TAG matches the passed tag.
     */
    public boolean isContextSpecific(byte cntxtTag) {
        if (!isContextSpecific()) {
            return false;
        }
        return ((tag & 0x01f) == cntxtTag);
    }

    boolean isPrivate()        { return ((tag & 0x0c0) == 0x0c0); }

    /** Returns true iff the CONSTRUCTED bit is set in the type tag. */
    public boolean isConstructed()    { return ((tag & 0x020) == 0x020); }

    /**
     * Returns true iff the CONSTRUCTED TAG matches the passed tag.
     */
    public boolean isConstructed(byte constructedTag) {
        if (!isConstructed()) {
            return false;
        }
        return ((tag & 0x01f) == constructedTag);
    }

    /**
     * Creates a PrintableString or UTF8string DER value from a string
     */
    public DerValue(String value) {
        this(isPrintableString(value) ? tag_PrintableString : tag_UTF8String,
                value);
    }

    public static boolean isPrintableString(String value) {
        for (int i = 0; i < value.length(); i++) {
            if (!isPrintableStringChar(value.charAt(i))) {
                return false;
            }
        }
        return true;
    }

    /**
     * Creates a string type DER value from a String object
     * @param stringTag the tag for the DER value to create
     * @param value the String object to use for the DER value
     */
    public DerValue(byte stringTag, String value) {
        final Charset charset;

        tag = stringTag;

        switch (stringTag) {
            case tag_PrintableString:
            case tag_IA5String:
            case tag_GeneralString:
                charset = US_ASCII;
                break;
            case tag_T61String:
                charset = ISO_8859_1;
                break;
            case tag_BMPString:
                charset = UTF_16BE;
                break;
            case tag_UTF8String:
                charset = UTF_8;
                break;
            case tag_UniversalString:
                charset = Charset.forName("UTF_32BE");
                break;
            default:
                throw new IllegalArgumentException("Unsupported DER string type");
        }

        buffer = value.getBytes(charset);
        start = 0;
        end = buffer.length;
        allowBER = false;
        this.data = new DerInputStream(this);
    }

    // Creates a DerValue from a tag and some DER-encoded data w/ additional
    // arg to control whether DER checks are enforced.
    DerValue(byte tag, byte[] buffer, boolean allowBER) {
        this(tag, buffer, 0, buffer.length, allowBER);
    }

    DerValue(byte tag, byte[] buffer, int start, int end, boolean allowBER) {
        this.tag = tag;
        this.buffer = buffer;
        this.start = start;
        this.end = end;
        this.allowBER = allowBER;
        this.data = new DerInputStream(this);
    }

    /**
     * Creates a DerValue from a tag and some DER-encoded data.
     *
     * @param tag the DER type tag
     * @param buffer the DER-encoded data
     */
    public DerValue(byte tag, byte[] buffer) {
        this(tag, buffer.clone(), true);
    }

    // Get an ASN.1/DER encoded datum from a buffer w/ additional
    // arg to control whether DER checks are enforced.
    DerValue(byte[] buf, boolean allowBER) throws IOException {
        this(buf, 0, buf.length, allowBER);
    }

    /**
     * Get an ASN.1/DER encoded datum from a buffer.  The
     * entire buffer must hold exactly one datum, including
     * its tag and length.
     *
     * @param buf buffer holding a single DER-encoded datum.
     */
    public DerValue(byte[] buf) throws IOException {
        this(buf.clone(), true);
    }

    // Get an ASN.1/DER encoded datum from part of a buffer w/ additional
    // arg to control whether DER checks are enforced.
    DerValue(byte[] buf, int offset, int len, boolean allowBER) throws IOException {
        this(buf, offset, len, allowBER, true);
    }

    DerValue(byte[] buf, int offset, int len, boolean allowBER, boolean noMore) throws IOException {
        if (len < 2) {
            throw new IOException("Too short " + len);
        }
        int pos = offset;
        tag = buf[pos++];
        int length;
        int lenByte = buf[pos++];

        if (lenByte == (byte)0x80) {
            length = -1;
        } else if ((lenByte & 0x080) == 0x00) { // short form, 1 byte datum
            length = lenByte;
        } else {                     // long form or indefinite
            lenByte &= 0x07f;
            if (lenByte == 0) {
                length = -1;
            } else if (lenByte < 0 || lenByte > 4) {
                throw new IOException("incorrect DER encoding");
            } else {
                if (len < 2 + lenByte) {
                    throw new IOException("incorrect DER encoding");
                }
                length = 0x0ff & buf[pos++];
                lenByte--;
                if (length == 0 && !allowBER) {
                    // DER requires length value be encoded in minimum number of bytes
                    throw new IOException("Redundant length bytes found");
                }
                while (lenByte-- > 0) {
                    length <<= 8;
                    length += 0x0ff & buf[pos++];
                }
                if (length < 0) {
                    throw new IOException("Invalid length bytes");
                } else if (length <= 127 && !allowBER) {
                    throw new IOException("Should use short form for length");
                }
            }
        }
        if (length == -1) { // indefinite length encoding found
            if (!allowBER) {
                throw new IOException
                        ("Indefinite length encoding not supported");
            }
            InputStream in = new ByteArrayInputStream(
                    DerIndefLenConverter.convertStream(
                            new ByteArrayInputStream(buf, pos, len - (pos - offset)), (byte)lenByte, tag));
            if (tag != in.read())
                throw new IOException
                        ("Indefinite length encoding not supported");
            length = DerInputStream.getDefiniteLength(in);
            this.buffer = IOUtils.readExactlyNBytes(in, length);
            this.start = 0;
            this.end = length;
            this.allowBER = true;
        } else {
            if (len - length < pos - offset) {
                throw new EOFException("Too little");
            }
            if (len - length > pos - offset && noMore) {
                throw new IOException("Too much");
            }
            this.buffer = buf;
            this.start = pos;
            this.end = pos + length;
            this.allowBER = allowBER;
        }
        this.data = new DerInputStream(this);
    }

    // Get an ASN1/DER encoded datum from an input stream w/ additional
    // arg to control whether DER checks are enforced.
    DerValue(InputStream in, boolean allowBER) throws IOException {
        this.tag = (byte)in.read();
        byte lenByte = (byte)in.read();
        int length = DerInputStream.getLength(lenByte, in);
        if (length == -1) { // indefinite length encoding found
            in = new ByteArrayInputStream(
                    DerIndefLenConverter.convertStream(in, lenByte, tag));
            if (tag != in.read())
                throw new IOException
                        ("Indefinite length encoding not supported");
            length = DerInputStream.getDefiniteLength(in);
        }
        this.buffer = IOUtils.readExactlyNBytes(in, length);
        this.start = 0;
        this.end = length;
        this.allowBER = allowBER;
        this.data = new DerInputStream(this);
        System.out.println(this);
    }

    /**
     * Get an ASN1/DER encoded datum from an input stream.  The
     * stream may have additional data following the encoded datum.
     * In case of indefinite length encoded datum, the input stream
     * must hold only one datum.
     *
     * @param in the input stream holding a single DER datum,
     *  which may be followed by additional data
     */
    public DerValue(InputStream in) throws IOException {
        this(in, true);
    }

    /**
     * Encode an ASN1/DER encoded datum onto a DER output stream.
     */
    public void encode(DerOutputStream out) throws IOException {
        out.write(tag);
        out.putLength(end - start);
        out.write(buffer, start, end - start);
        data.pos = data.end; // Compatibility. Reach end.
    }

    public final DerInputStream getData() {
        return data;
    }

    public final byte getTag() {
        return tag;
    }

    /**
     * Returns an ASN.1 BOOLEAN
     *
     * @return the boolean held in this DER value
     */
    public boolean getBoolean() throws IOException {
        if (tag != tag_Boolean) {
            throw new IOException("DerValue.getBoolean, not a BOOLEAN " + tag);
        }
        if (end - start != 1) {
            throw new IOException("DerValue.getBoolean, invalid length "
                                        + (end - start));
        }
        data.pos = data.end; // Compatibility. Reach end.
        return buffer[start] != 0;
    }

    /**
     * Returns an ASN.1 OBJECT IDENTIFIER.
     *
     * @return the OID held in this DER value
     */
    public ObjectIdentifier getOID() throws IOException {
        if (tag != tag_ObjectId)
            throw new IOException("DerValue.getOID, not an OID " + tag);
        data.pos = data.end; // Compatibility. Reach end.
        return new ObjectIdentifier(buffer, start, end);
    }

    /**
     * Returns an ASN.1 OCTET STRING
     *
     * @return the octet string held in this DER value
     */
    public byte[] getOctetString() throws IOException {

        if (tag != tag_OctetString && !isConstructed(tag_OctetString)) {
            throw new IOException(
                "DerValue.getOctetString, not an Octet String: " + tag);
        }
        // Note: do not attempt to call buffer.read(bytes) at all. There's a
        // known bug that it returns -1 instead of 0.
        if (end - start == 0) {
            return new byte[0];
        }

        data.pos = data.end; // Compatibility. Reach end.
        if (!isConstructed()) {
            return Arrays.copyOfRange(buffer, start, end);
        } else {
            ByteArrayOutputStream bout = new ByteArrayOutputStream();
            for (DerValue dv : new DerInputStream(this)) {
                bout.write(dv.getOctetString());
            }
            return bout.toByteArray();
        }
    }

    /**
     * Returns an ASN.1 INTEGER value as an integer.
     *
     * @return the integer held in this DER value.
     */
    public int getInteger() throws IOException {
        BigInteger result = getBigInteger();
        if (result.compareTo(BigInteger.valueOf(Integer.MIN_VALUE)) < 0) {
            throw new IOException("Integer below minimum valid value");
        }
        if (result.compareTo(BigInteger.valueOf(Integer.MAX_VALUE)) > 0) {
            throw new IOException("Integer exceeds maximum valid value");
        }
        return result.intValue();
    }

    /**
     * Returns an ASN.1 INTEGER value as a BigInteger.
     *
     * @return the integer held in this DER value as a BigInteger.
     */
    public BigInteger getBigInteger() throws IOException {
        return getBigInteger0(false);
    }

    /**
     * Returns an ASN.1 INTEGER value as a positive BigInteger.
     * This is just to deal with implementations that incorrectly encode
     * some values as negative.
     *
     * @return the integer held in this DER value as a BigInteger.
     */
    public BigInteger getPositiveBigInteger() throws IOException {
        return getBigInteger0(true);
    }

    private BigInteger getBigInteger0(boolean mustBePositive) throws IOException {
        if (tag != tag_Integer)
            throw new IOException("DerValue.getBigInteger, not an int " + tag);
        if (end == start) {
            throw new IOException("Invalid encoding: zero length Int value");
        }
        data.pos = data.end; // Compatibility. Reach end.
        if (!allowBER && (end - start >= 2 && (buffer[start] == 0) && (buffer[start + 1] >= 0))) {
            throw new IOException("Invalid encoding: redundant leading 0s");
        }
        return mustBePositive
                ? new BigInteger(1, buffer, start, end - start)
                : new BigInteger(buffer, start, end - start);
    }

    /**
     * Returns an ASN.1 ENUMERATED value.
     *
     * @return the integer held in this DER value.
     */
    public int getEnumerated() throws IOException {
        if (tag != tag_Enumerated) {
            throw new IOException("DerValue.getEnumerated, incorrect tag: "
                                  + tag);
        }
        // TODO
        return new BigInteger(1, buffer, start, end - start).intValue();
    }

    /**
     * Returns an ASN.1 BIT STRING value.  The bit string must be byte-aligned.
     *
     * @return the bit string held in this value
     */
    public byte[] getBitString() throws IOException {
        return getBitString(false);
    }

    /**
     * Returns an ASN.1 BIT STRING value that need not be byte-aligned.
     *
     * @return a BitArray representing the bit string held in this value
     */
    public BitArray getUnalignedBitString() throws IOException {
        return getUnalignedBitString(false);
    }

    /**
     * Returns the name component as a Java string, regardless of its
     * encoding restrictions (ASCII, T61, Printable, IA5, BMP, UTF8).
     */
    // TBD: Need encoder for UniversalString before it can be handled.
    public String getAsString() throws IOException {
        if (tag == tag_UTF8String)
            return getUTF8String();
        else if (tag == tag_PrintableString)
            return getPrintableString();
        else if (tag == tag_T61String)
            return getT61String();
        else if (tag == tag_IA5String)
            return getIA5String();
        else if (tag == tag_UniversalString)
          return getUniversalString();
        else if (tag == tag_BMPString)
            return getBMPString();
        else if (tag == tag_GeneralString)
            return getGeneralString();
        else
            return null;
    }

    /**
     * Returns an ASN.1 BIT STRING value, with the tag assumed implicit
     * based on the parameter.  The bit string must be byte-aligned.
     *
     * @param tagImplicit if true, the tag is assumed implicit.
     * @return the bit string held in this value
     */
    public byte[] getBitString(boolean tagImplicit) throws IOException {
        if (!tagImplicit) {
            if (tag != tag_BitString) {
                throw new IOException("DerValue.getBitString, not a bit string "
                        + tag);
            }
        }
        if (end == start) {
            throw new IOException("No padding");
        }
        int numOfPadBits = buffer[start];
        if ((numOfPadBits < 0) || (numOfPadBits > 7)) {
            throw new IOException("Invalid number of padding bits");
        }
        // minus the first byte which indicates the number of padding bits
        byte[] retval = Arrays.copyOfRange(buffer, start + 1, end);
        if (numOfPadBits != 0) {
            // get rid of the padding bits
            retval[end - start - 2] &= (0xff << numOfPadBits);
        }
        data.pos = data.end; // Compatibility. Reach end.
        return retval;
    }

    /**
     * Returns an ASN.1 BIT STRING value, with the tag assumed implicit
     * based on the parameter.  The bit string need not be byte-aligned.
     *
     * @param tagImplicit if true, the tag is assumed implicit.
     * @return the bit string held in this value
     */
    public BitArray getUnalignedBitString(boolean tagImplicit)
            throws IOException {
        if (!tagImplicit) {
            if (tag != tag_BitString) {
                throw new IOException("DerValue.getBitString, not a bit string "
                        + tag);
            }
        }
        if (end == start) {
            throw new IOException("No padding");
        }
        data.pos = data.end; // Compatibility. Reach end.
        if (end == start + 1) {
            return new BitArray(0);
        } else {
            int numOfPadBits = buffer[start];
            if ((numOfPadBits < 0) || (numOfPadBits > 7)) {
                throw new IOException("Invalid number of padding bits");
            }
            return new BitArray((end - start - 1) * 8 - numOfPadBits,
                    Arrays.copyOfRange(buffer, start + 1, end));
        }
    }

    /**
     * Helper routine to return all the bytes contained in the
     * DerInputStream associated with this object.
     */
    public byte[] getDataBytes() throws IOException {
        data.pos = data.end; // Compatibility. Reach end.
        return Arrays.copyOfRange(buffer, start, end);
    }

    private String readString0(Charset cs) {
        data.pos = data.end; // Compatibility. Reach end.
        return new String(buffer, start, end - start, cs);
    }
    /**
     * Returns an ASN.1 STRING value
     *
     * @return the printable string held in this value
     */
    public String getPrintableString()
    throws IOException {
        if (tag != tag_PrintableString)
            throw new IOException(
                "DerValue.getPrintableString, not a string " + tag);

        return readString0(US_ASCII);
    }

    /**
     * Returns an ASN.1 T61 (Teletype) STRING value
     *
     * @return the teletype string held in this value
     */
    public String getT61String() throws IOException {
        if (tag != tag_T61String)
            throw new IOException(
                "DerValue.getT61String, not T61 " + tag);

        return readString0(ISO_8859_1);
    }

    /**
     * Returns an ASN.1 IA5 (ASCII) STRING value
     *
     * @return the ASCII string held in this value
     */
    public String getIA5String() throws IOException {
        if (tag != tag_IA5String)
            throw new IOException(
                "DerValue.getIA5String, not IA5 " + tag);

        return readString0(US_ASCII);
    }

    /**
     * Returns the ASN.1 BMP (Unicode) STRING value as a Java string.
     *
     * @return a string corresponding to the encoded BMPString held in
     * this value
     */
    public String getBMPString() throws IOException {
        if (tag != tag_BMPString)
            throw new IOException(
                "DerValue.getBMPString, not BMP " + tag);

        // BMPString is the same as Unicode in big endian, unmarked
        // format.
        return readString0(UTF_16BE);
    }

    /**
     * Returns the ASN.1 UTF-8 STRING value as a Java String.
     *
     * @return a string corresponding to the encoded UTF8String held in
     * this value
     */
    public String getUTF8String() throws IOException {
        if (tag != tag_UTF8String)
            throw new IOException(
                "DerValue.getUTF8String, not UTF-8 " + tag);

        return readString0(UTF_8);
    }

    /**
     * Returns the ASN.1 GENERAL STRING value as a Java String.
     *
     * @return a string corresponding to the encoded GeneralString held in
     * this value
     */
    public String getGeneralString() throws IOException {
        if (tag != tag_GeneralString)
            throw new IOException(
                "DerValue.getGeneralString, not GeneralString " + tag);

        return readString0(US_ASCII);
    }

    /**
     * Returns the ASN.1 UNIVERSAL (UTF-32) STRING value as a Java String.
     *
     * @return a string corresponding to the encoded UniversalString held in
     * this value or an empty string if UTF_32BE is not a supported character
     * set.
     */
    public String getUniversalString() throws IOException {
        if (tag != tag_UniversalString)
            throw new IOException(
                "DerValue.getUniversalString, not UniversalString " + tag);
        try {
            Charset cset = Charset.forName("UTF_32BE");
            return readString0(cset);
        } catch (IllegalCharsetNameException | UnsupportedCharsetException e) {
            return "";
        }
    }

    private Date getTime(int len, boolean generalized) throws IOException {

        /*
         * UTC time encoded as ASCII chars:
         *       YYMMDDhhmmZ
         *       YYMMDDhhmmssZ
         *       YYMMDDhhmm+hhmm
         *       YYMMDDhhmm-hhmm
         *       YYMMDDhhmmss+hhmm
         *       YYMMDDhhmmss-hhmm
         * UTC Time is broken in storing only two digits of year.
         * If YY < 50, we assume 20YY;
         * if YY >= 50, we assume 19YY, as per RFC 5280.
         *
         * Generalized time has a four-digit year and allows any
         * precision specified in ISO 8601. However, for our purposes,
         * we will only allow the same format as UTC time, except that
         * fractional seconds (millisecond precision) are supported.
         */

        int year, month, day, hour, minute, second, millis;
        String type = null;

        int pos = start;
        if (generalized) {
            type = "Generalized";
            year = 1000 * Character.digit((char)buffer[pos++], 10);
            year += 100 * Character.digit((char)buffer[pos++], 10);
            year += 10 * Character.digit((char)buffer[pos++], 10);
            year += Character.digit((char)buffer[pos++], 10);
            len -= 2; // For the two extra YY
        } else {
            type = "UTC";
            year = 10 * Character.digit((char)buffer[pos++], 10);
            year += Character.digit((char)buffer[pos++], 10);

            if (year < 50)              // origin 2000
                year += 2000;
            else
                year += 1900;   // origin 1900
        }

        month = 10 * Character.digit((char)buffer[pos++], 10);
        month += Character.digit((char)buffer[pos++], 10);

        day = 10 * Character.digit((char)buffer[pos++], 10);
        day += Character.digit((char)buffer[pos++], 10);

        hour = 10 * Character.digit((char)buffer[pos++], 10);
        hour += Character.digit((char)buffer[pos++], 10);

        minute = 10 * Character.digit((char)buffer[pos++], 10);
        minute += Character.digit((char)buffer[pos++], 10);

        len -= 10; // YYMMDDhhmm

        /*
         * We allow for non-encoded seconds, even though the
         * IETF-PKIX specification says that the seconds should
         * always be encoded even if it is zero.
         */

        millis = 0;
        if (len > 2) {
            second = 10 * Character.digit((char)buffer[pos++], 10);
            second += Character.digit((char)buffer[pos++], 10);
            len -= 2;
            // handle fractional seconds (if present)
            if (buffer[pos] == '.' || buffer[pos] == ',') {
                len --;
                pos++;
                int precision = 0;
                while (buffer[pos] != 'Z' &&
                        buffer[pos] != '+' &&
                        buffer[pos] != '-') {
                    // Validate all digits in the fractional part but
                    // store millisecond precision only
                    int thisDigit = Character.digit((char)buffer[pos], 10);
                    precision++;
                    pos++;
                    switch (precision) {
                        case 1:
                            millis += 100 * thisDigit;
                            break;
                        case 2:
                            millis += 10 * thisDigit;
                            break;
                        case 3:
                            millis += thisDigit;
                            break;
                    }
                }
                if (precision == 0) {
                    throw new IOException("Parse " + type +
                            " time, empty fractional part");
                }
                len -= precision;
            }
        } else
            second = 0;

        if (month == 0 || day == 0
                || month > 12 || day > 31
                || hour >= 24 || minute >= 60 || second >= 60)
            throw new IOException("Parse " + type + " time, invalid format");

        /*
         * Generalized time can theoretically allow any precision,
         * but we're not supporting that.
         */
        CalendarSystem gcal = CalendarSystem.getGregorianCalendar();
        CalendarDate date = gcal.newCalendarDate(null); // no time zone
        date.setDate(year, month, day);
        date.setTimeOfDay(hour, minute, second, millis);
        long time = gcal.getTime(date);

        /*
         * Finally, "Z" or "+hhmm" or "-hhmm" ... offsets change hhmm
         */
        if (! (len == 1 || len == 5))
            throw new IOException("Parse " + type + " time, invalid offset");

        int hr, min;

        switch (buffer[pos++]) {
            case '+':
                hr = 10 * Character.digit((char)buffer[pos++], 10);
                hr += Character.digit((char)buffer[pos++], 10);
                min = 10 * Character.digit((char)buffer[pos++], 10);
                min += Character.digit((char)buffer[pos++], 10);

                if (hr >= 24 || min >= 60)
                    throw new IOException("Parse " + type + " time, +hhmm");

                time -= ((hr * 60) + min) * 60 * 1000;
                break;

            case '-':
                hr = 10 * Character.digit((char)buffer[pos++], 10);
                hr += Character.digit((char)buffer[pos++], 10);
                min = 10 * Character.digit((char)buffer[pos++], 10);
                min += Character.digit((char)buffer[pos++], 10);

                if (hr >= 24 || min >= 60)
                    throw new IOException("Parse " + type + " time, -hhmm");

                time += ((hr * 60) + min) * 60 * 1000;
                break;

            case 'Z':
                break;

            default:
                throw new IOException("Parse " + type + " time, garbage offset");
        }
        return new Date(time);
    }

    public void getNull() throws IOException {
        if (tag != tag_Null) {
            throw new IOException("DerValue.getUTCTime, not a UtcTime: " + tag);
        }
        if (end != start) {
            throw new IOException("DER UTC Time length error");
        }
    }

    /**
     * Returns a Date if the DerValue is UtcTime.
     *
     * @return the Date held in this DER value
     */
    public Date getUTCTime() throws IOException {
        if (tag != tag_UtcTime) {
            throw new IOException("DerValue.getUTCTime, not a UtcTime: " + tag);
        }
        if (end - start < 11 || end - start > 17)
            throw new IOException("DER UTC Time length error");

        data.pos = data.end; // Compatibility. Reach end.
        return getTime(end - start, false);
    }

    /**
     * Returns a Date if the DerValue is GeneralizedTime.
     *
     * @return the Date held in this DER value
     */
    public Date getGeneralizedTime() throws IOException {
        if (tag != tag_GeneralizedTime) {
            throw new IOException(
                "DerValue.getGeneralizedTime, not a GeneralizedTime: " + tag);
        }
        if (end - start < 13)
            throw new IOException("DER Generalized Time length error");

        data.pos = data.end; // Compatibility. Reach end.
        return getTime(end - start, true);
    }

    /**
     * Bitwise equality comparison.  DER encoded values have a single
     * encoding, so that bitwise equality of the encoded values is an
     * efficient way to establish equivalence of the unencoded values.
     *
     * @param o the object being compared with this one
     */
    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof DerValue)) {
            return false;
        }
        DerValue other = (DerValue) o;
        if (tag != other.tag) {
            return false;
        }
        if (buffer == other.buffer && start == other.start && end == other.end) {
            return true;
        }
        return Arrays.equals(buffer, start, end, other.buffer, other.start, other.end);
    }

    /**
     * Returns a printable representation of the value.
     *
     * @return printable representation of the value
     */
    @Override
    public String toString() {
        return String.format("DerValue(%02x, %s, %d, 5d)",
                0xff & tag, buffer, start, end);
    }

    /**
     * Returns a DER-encoded value, such that if it's passed to the
     * DerValue constructor, a value equivalent to "this" is returned.
     *
     * @return DER-encoded value, including tag and length.
     */
    public byte[] toByteArray() throws IOException {
        DerOutputStream out = new DerOutputStream();
        encode(out);
        data.pos = data.start; // encode go last, should go back
        return out.toByteArray();
    }

    /**
     * For "set" and "sequence" types, this function may be used
     * to return a DER stream of the members of the set or sequence.
     * This operation is not supported for primitive types such as
     * integers or bit strings.
     */
    public DerInputStream toDerInputStream() throws IOException {
        if (tag == tag_Sequence || tag == tag_Set)
            return data;
        throw new IOException("toDerInputStream rejects tag type " + tag);
    }

    /**
     * Get the length of the encoded value.
     */
    public int length() {
        return end - start;
    }

    /**
     * Determine if a character is one of the permissible characters for
     * PrintableString:
     * A-Z, a-z, 0-9, space, apostrophe (39), left and right parentheses,
     * plus sign, comma, hyphen, period, slash, colon, equals sign,
     * and question mark.
     *
     * Characters that are *not* allowed in PrintableString include
     * exclamation point, quotation mark, number sign, dollar sign,
     * percent sign, ampersand, asterisk, semicolon, less than sign,
     * greater than sign, at sign, left and right square brackets,
     * backslash, circumflex (94), underscore, back quote (96),
     * left and right curly brackets, vertical line, tilde,
     * and the control codes (0-31 and 127).
     *
     * This list is based on X.680 (the ASN.1 spec).
     */
    public static boolean isPrintableStringChar(char ch) {
        if ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
            (ch >= '0' && ch <= '9')) {
            return true;
        } else {
            switch (ch) {
                case ' ':       /* space */
                case '\'':      /* apostrophe */
                case '(':       /* left paren */
                case ')':       /* right paren */
                case '+':       /* plus */
                case ',':       /* comma */
                case '-':       /* hyphen */
                case '.':       /* period */
                case '/':       /* slash */
                case ':':       /* colon */
                case '=':       /* equals */
                case '?':       /* question mark */
                    return true;
                default:
                    return false;
            }
        }
    }

    /**
     * Create the tag of the attribute.
     *
     * @param tagClass the tag class type, one of UNIVERSAL, CONTEXT,
     *               APPLICATION or PRIVATE
     * @param form if true, the value is constructed, otherwise it
     * is primitive.
     * @param val the tag value
     */
    public static byte createTag(byte tagClass, boolean form, byte val) {
        byte tag = (byte)(tagClass | val);
        if (form) {
            tag |= (byte)0x20;
        }
        return (tag);
    }

    /**
     * Set the tag of the attribute. Commonly used to reset the
     * tag value used for IMPLICIT encodings.
     *
     * @param tag the tag value
     */
    public void resetTag(byte tag) {
        this.tag = tag;
    }

    /**
     * Returns a hashcode for this DerValue.
     *
     * @return a hashcode for this DerValue.
     */
    @Override
    public int hashCode() {
        return toString().hashCode();
    }

    public DerValue[] subs(byte expectedTag) throws IOException {
        if (expectedTag != 0 && expectedTag != tag) {
            throw new IOException("Not constructed");
        }
        List<DerValue> result = new ArrayList<>();
        DerInputStream dis = new DerInputStream(this);
        while (dis.available() > 0) {
            result.add(dis.getDerValue());
        }
        return result.toArray(new DerValue[result.size()]);
    }
}
