/*
 * Copyright (c) 1998, 2020, Oracle and/or its affiliates. All rights reserved.
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

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Arrays;

/**
 * A package private utility class to convert indefinite length DER
 * encoded byte arrays to definite length DER encoded byte arrays.
 *
 * This assumes that the basic data structure is "tag, length, value"
 * triplet. In the case where the length is "indefinite", terminating
 * end-of-contents bytes (EOC) are expected.
 *
 * @author Hemma Prafullchandra
 */
class DerIndefLenConverter {

    private static final int LEN_LONG            = 0x80; // bit 8 set
    private static final int LEN_MASK            = 0x7f; // bits 7 - 1

    private final byte[] data;

    private byte[] newData;
    private int newDataPos, dataPos, dataSize, index;
    private int unresolved = 0;

    // After an indefinite length is seen, the current dataPos is added in this
    // list. When its matching EOC is seen, the dataPos is substituted into the
    // calculated definite length.
    private ArrayList<Object> ndefsList = new ArrayList<>();

    // The total length change between the original encoding and the new
    // encoding. Each change is a "80 00 00" to a definite length.
    private int totalLengthChange = 0;

    private boolean isEOC(int tag) {
        return tag == 0;
    }

    // if bit 8 is set then it implies either indefinite length or long form
    private static boolean isLongForm(int lengthByte) {
        return ((lengthByte & LEN_LONG) == LEN_LONG);
    }

    /*
     * private constructor
     */
    private DerIndefLenConverter(byte[] indefData) {
        data = indefData;
        dataPos=0;
        dataSize = data.length;
    }

    /**
     * Checks whether the given length byte is of the form
     * <em>Indefinite</em>.
     *
     * @param lengthByte the length byte from a DER encoded
     *        object.
     * @return true if the byte is of Indefinite form otherwise
     *         returns false.
     */
    static boolean isIndefinite(int lengthByte) {
        return (isLongForm(lengthByte) && ((lengthByte & LEN_MASK) == 0));
    }

    /**
     * Parse the tag. If it is EOC then substitute the dataPos of its matching
     * indefinite length in {@code ndefsList} to a definite length.
     */
    private void parseTag() throws IOException {
        if (isEOC(data[dataPos]) && (data[dataPos + 1] == 0)) {
            int lengthChanged = 0;
            Object elem = null;
            int i;
            for (i = ndefsList.size() - 1; i  >= 0; i--) {
                elem = ndefsList.get(i);
                if (elem instanceof Integer) {
                    // Most recent dataPos that does not have a matching EOC
                    break;
                } else {
                    // For matched EOCs, cumulate the length changes
                    lengthChanged += ((byte[])elem).length - 3;
                }
            }
            if (i < 0) {
                throw new IOException("EOC does not have matching " +
                                      "indefinite-length tag");
            }
            int sectionLen = dataPos - (Integer)elem + lengthChanged;
            byte[] sectionLenBytes = getLengthBytes(sectionLen);
            ndefsList.set(i, sectionLenBytes);
            unresolved--;

            // Add the number of bytes required to represent this section
            // to the total number of length bytes,
            // and subtract the indefinite-length tag (1 byte) and
            // EOC bytes (2 bytes) for this section
            totalLengthChange += (sectionLenBytes.length - 3);
        }
        dataPos++;
    }

    /**
     * Copy the next tag from data to newData, skipping zero or more EOC.
     */
    private void writeTag() {
        int tag = data[dataPos++];
        if (isEOC(tag) && (data[dataPos] == 0)) {
            dataPos++;  // skip length
            if (dataPos == dataSize) {
                return;
            }
            writeTag();
        } else {
            newData[newDataPos++] = (byte) tag;
        }
    }

    /**
     * Parse the length and if it is an indefinite length then add
     * the current position to the {@code ndefsList} list.
     *
     * @return the length of definite length data next, or -1 if there is
     *         not enough bytes to determine it
     * @throws IOException if invalid data is read
     */
    private int parseLength() throws IOException {
        if (dataPos == dataSize) {
            // TODO if not enough bytes here, will this fail?
            return 0;
        }
        int lenByte = data[dataPos++] & 0xff;
        if (isIndefinite(lenByte)) {
            ndefsList.add(dataPos);
            unresolved++;
            return 0;
        }
        int curLen = 0;
        if (isLongForm(lenByte)) {
            lenByte &= LEN_MASK;
            if (lenByte > 4) {
                throw new IOException("Too much data");
            }
            if ((dataSize - dataPos) < (lenByte + 1)) {
                return -1;
            }
            for (int i = 0; i < lenByte; i++) {
                curLen = (curLen << 8) + (data[dataPos++] & 0xff);
            }
            if (curLen < 0) {
                throw new IOException("Invalid length bytes");
            }
        } else {
           curLen = (lenByte & LEN_MASK);
        }
        return curLen;
    }

    /**
     * Write the length and if it is an indefinite length
     * then write the definite length in {@code ndefsList}.
     * Then, write the value.
     */
    private void writeLengthAndValue() throws IOException {
        if (dataPos == dataSize) {
            // happens when an EOC at the end is read
            return;
        }
        int curLen = 0;
        int lenByte = data[dataPos++] & 0xff;
        if (isIndefinite(lenByte)) {
            byte[] lenBytes = (byte[])ndefsList.get(index++);
            System.arraycopy(lenBytes, 0, newData, newDataPos,
                             lenBytes.length);
            newDataPos += lenBytes.length;
            return;
        }
        if (isLongForm(lenByte)) {
            lenByte &= LEN_MASK;
            for (int i = 0; i < lenByte; i++) {
                curLen = (curLen << 8) + (data[dataPos++] & 0xff);
            }
            if (curLen < 0) {
                throw new IOException("Invalid length bytes");
            }
        } else {
            curLen = (lenByte & LEN_MASK);
        }
        writeLength(curLen);
        writeValue(curLen);
    }

    private void writeLength(int curLen) {
        if (curLen < 128) {
            newData[newDataPos++] = (byte)curLen;

        } else if (curLen < (1 << 8)) {
            newData[newDataPos++] = (byte)0x81;
            newData[newDataPos++] = (byte)curLen;

        } else if (curLen < (1 << 16)) {
            newData[newDataPos++] = (byte)0x82;
            newData[newDataPos++] = (byte)(curLen >> 8);
            newData[newDataPos++] = (byte)curLen;

        } else if (curLen < (1 << 24)) {
            newData[newDataPos++] = (byte)0x83;
            newData[newDataPos++] = (byte)(curLen >> 16);
            newData[newDataPos++] = (byte)(curLen >> 8);
            newData[newDataPos++] = (byte)curLen;

        } else {
            newData[newDataPos++] = (byte)0x84;
            newData[newDataPos++] = (byte)(curLen >> 24);
            newData[newDataPos++] = (byte)(curLen >> 16);
            newData[newDataPos++] = (byte)(curLen >> 8);
            newData[newDataPos++] = (byte)curLen;
        }
    }

    private byte[] getLengthBytes(int curLen) {
        byte[] lenBytes;
        int i = 0;

        if (curLen < 128) {
            lenBytes = new byte[1];
            lenBytes[i++] = (byte)curLen;

        } else if (curLen < (1 << 8)) {
            lenBytes = new byte[2];
            lenBytes[i++] = (byte)0x81;
            lenBytes[i++] = (byte)curLen;

        } else if (curLen < (1 << 16)) {
            lenBytes = new byte[3];
            lenBytes[i++] = (byte)0x82;
            lenBytes[i++] = (byte)(curLen >> 8);
            lenBytes[i++] = (byte)curLen;

        } else if (curLen < (1 << 24)) {
            lenBytes = new byte[4];
            lenBytes[i++] = (byte)0x83;
            lenBytes[i++] = (byte)(curLen >> 16);
            lenBytes[i++] = (byte)(curLen >> 8);
            lenBytes[i++] = (byte)curLen;

        } else {
            lenBytes = new byte[5];
            lenBytes[i++] = (byte)0x84;
            lenBytes[i++] = (byte)(curLen >> 24);
            lenBytes[i++] = (byte)(curLen >> 16);
            lenBytes[i++] = (byte)(curLen >> 8);
            lenBytes[i++] = (byte)curLen;
        }

        return lenBytes;
    }

    /**
     * Parse the value;
     */
    private void parseValue(int curLen) {
        dataPos += curLen;
    }

    /**
     * Write the value;
     */
    private void writeValue(int curLen) {
        System.arraycopy(data, dataPos, newData, newDataPos, curLen);
        dataPos += curLen;
        newDataPos += curLen;
    }

    private byte[] convertBytesInternal() throws IOException {
        int unused = 0;

        // parse and set up the list of all the indefinite-lengths
        while (dataPos < dataSize) {
            if (dataPos + 2 > dataSize) {
                // There should be at least one tag and one length
                return null;
            }
            parseTag();
            int len = parseLength();
            if (len < 0) {
                return null;
            }
            parseValue(len);
            if (unresolved == 0) {
                unused = dataSize - dataPos;
                dataSize = dataPos;
                break;
            }
        }

        if (unresolved != 0) {
            return null;
        }

        newData = new byte[dataSize + totalLengthChange + unused];
        dataPos=0; newDataPos=0; index=0;

        // write out the new byte array replacing all the indefinite-lengths
        // and EOCs
        while (dataPos < dataSize) {
           writeTag();
           writeLengthAndValue();
        }
        System.arraycopy(data, dataSize,
                         newData, dataSize + totalLengthChange, unused);

        return newData;
    }

    /**
     * Converts a indefinite length DER encoded byte array to
     * a definte length DER encoding.
     *
     * @param indefData the byte array holding the indefinite
     *        length encoding.
     * @return the byte array containing the definite length
     *         DER encoding, or null if there is not enough data.
     * @exception IOException on parsing or re-writing errors.
     */
    public static byte[] convertBytes(byte[] indefData) throws IOException {
        return new DerIndefLenConverter(indefData).convertBytesInternal();
    }

    /**
     * Read the input stream into a DER byte array. If an indef len BER is
     * not resolved this method will try to read more data until EOF is reached.
     * This may block.
     *
     * @param in the input stream with tag and lenByte already read
     * @param lenByte the length of the length field to remember
     * @param tag the tag to remember
     * @return a DER byte array
     * @throws IOException if not all indef len BER
     *         can be resolved or another I/O error happens
     */
    public static byte[] convertStream(InputStream in, byte lenByte, byte tag)
            throws IOException {
        int offset = 2;     // for tag and length bytes
        int readLen = in.available();
        byte[] indefData = new byte[readLen + offset];
        indefData[0] = tag;
        indefData[1] = lenByte;
        while (true) {
            int bytesRead = in.readNBytes(indefData, offset, readLen);
            if (bytesRead != readLen) {
                readLen = bytesRead;
                indefData = Arrays.copyOf(indefData, offset + bytesRead);
            }
            byte[] result = DerIndefLenConverter.convertBytes(indefData);
            if (result == null) {
                int next = in.read(); // This could block, but we need more
                if (next == -1) {
                    throw new IOException("not all indef len BER resolved");
                }
                int more = in.available();
                // expand array to include next and more
                indefData = Arrays.copyOf(indefData, offset + readLen + 1 + more);
                indefData[offset + readLen] = (byte)next;
                offset = offset + readLen + 1;
                readLen = more;
            } else {
                return result;
            }
        }
    }
}
