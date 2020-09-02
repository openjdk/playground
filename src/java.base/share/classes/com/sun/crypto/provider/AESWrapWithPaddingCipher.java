/*
 * Copyright (c) 2020, Oracle and/or its affiliates. All rights reserved.
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

package com.sun.crypto.provider;

import java.util.Arrays;
import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;

/**
 * This class implements the AESKeyWrapWithPadding algorithm as defined
 * in <a href=https://tools.ietf.org/html/rfc5649>
 * "Advanced Encryption Standard (AES) Key Wrap with Padding Algorithm".
 * Note: only <code>KWP</code> mode and <code>NoPadding</code> padding
 * can be used for this algorithm.
 */
abstract class AESWrapWithPaddingCipher extends KeyWrapBaseCipher {

    // for AES/KWP/NoPadding
    public static final class General extends AESWrapWithPaddingCipher {
        public General() {
            super(-1, "KWP");
        }
    }

    // for AES_128/KWP/NoPadding
    public static final class AES128 extends AESWrapWithPaddingCipher {
        public AES128() {
            super(16, "KWP");
        }
    }

    // for AES_192/KWP/NoPadding
    public static final class AES192 extends AESWrapWithPaddingCipher {
        public AES192() {
            super(24, "KWP");
        }
    }

    // for AES_256/KWP/NoPadding
    public static final class AES256 extends AESWrapWithPaddingCipher {
        public AES256() {
            super(32, "KWP");
        }
    }

    // the last four bytes will be overwritten with input length
    private static final byte[] ICV2 = {
        (byte) 0xA6, (byte) 0x59, (byte) 0x59, (byte) 0xA6,
        (byte) 0, (byte) 0, (byte) 0, (byte) 0,
    };

    /**
     * Creates an instance of AES/KWP/NoPadding cipher.
     */
    public AESWrapWithPaddingCipher(int keySize, String mode) {
        super(new AESCrypt(), keySize, mode, "NoPadding");
    }

    private static byte[] generateIV(int inLen) {
        byte[] iv = ICV2.clone();
        iv[4] = (byte) (inLen >>> 24);
        iv[5] = (byte) (inLen >>> 16);
        iv[6] = (byte) (inLen >>> 8);
        iv[7] = (byte) inLen;
        return iv;
    }

    private static int validateIV(byte[] iv) throws IllegalBlockSizeException {
        // check ICV2 and fail if no match
        boolean match = true;
        for (int i = 0; i < 4; i++) {
             if (ICV2[i] != iv[i]) {
                 match = false;
             }
        }
        if (!match) {
            throw new IllegalBlockSizeException("Integrity check failed");
        }
        int outLen = iv[4];
        for (int k = 5; k < SEMI_BLKSIZE; k++) {
            if (outLen != 0) {
                outLen <<= SEMI_BLKSIZE;
            }
            byte v = iv[k];
            if (v != 0) {
                outLen += v;
            }
        }
        return outLen;
    }

    protected int implGetOutputSize(int inputLen) {
        // XXX allow inputLen == 0?
        // can only return an upper-limit if not initialized yet.
        int result = 0;
        if (decrypting) {
            // the actual length is only available after decryption
            // this length may contain padding bytes
            result = inputLen - SEMI_BLKSIZE;
        } else {
            result = Math.addExact(inputLen, SEMI_BLKSIZE);

            int res = inputLen % SEMI_BLKSIZE;
            if (res != 0) {
                result = Math.addExact(result, SEMI_BLKSIZE - res);
            }
            System.out.println("implGetOutputSize got " + result);
        }
        return (result < 0? 0 : result);
    }

    // does single-part encryption
    // NOTE: assumed that output buffer size is already checked by caller
    protected int implEncrypt(byte[] in, int inOfs, int inLen, byte[] out,
            int outOfs)
        throws IllegalBlockSizeException {

        if (inLen < 1) {
            throw new IllegalBlockSizeException
                ("data should have at least 1 byte");
        }
        // Error out if in==out for now
        if (in == out) {
            throw new ProviderException("Encryption in-place is unsupported");
        }

        // calculate output size
        int outLen = implGetOutputSize(inLen);
        byte[] iv = generateIV(inLen);
        if (outLen <= BLKSIZE) {
            System.arraycopy(iv, 0, out, outOfs, SEMI_BLKSIZE);
            System.arraycopy(in, inOfs, out, outOfs + SEMI_BLKSIZE, inLen);
            int padLen = outLen - inLen - SEMI_BLKSIZE;
            if (padLen != 0) {
                System.out.println("PadLen = " + padLen);
                int startIdx = outOfs + SEMI_BLKSIZE + inLen;
                Arrays.fill(out, startIdx, startIdx + padLen, (byte)0);
            }
            cipher.encryptBlock(out, outOfs, out, outOfs);
        } else {
            W(iv, in, inOfs, inLen, out, outOfs, cipher);
        }
        return outLen;
    }

    // does single-part decryption
    // NOTE: assumed that output buffer size is already checked by caller
    protected int implDecrypt(byte[] in, int inOfs, int inLen,
            byte[] out, int outOfs)
        throws IllegalBlockSizeException {

        if (inLen < BLKSIZE || inLen % SEMI_BLKSIZE != 0) {
            throw new IllegalBlockSizeException
                ("data should be at least 16 bytes and multiples of 8");
        }

        // We cannot directly use 'out' as we don't know whether there
        // are padding bytes
        byte[] ivOut;
        byte[] outBuf;
        if (inLen == BLKSIZE) {
            byte[] buf = new byte[BLKSIZE];
            cipher.decryptBlock(in, inOfs, buf, 0);
            ivOut = Arrays.copyOfRange(buf, 0, SEMI_BLKSIZE);
            outBuf = Arrays.copyOfRange(buf, SEMI_BLKSIZE, BLKSIZE);
        } else {
            ivOut = new byte[SEMI_BLKSIZE];
            outBuf = W_INV(in, inOfs, inLen, ivOut, cipher);
        }

        int outLen = validateIV(ivOut);
        // check padding bytes
        int padLen = inLen - SEMI_BLKSIZE - outLen;
        for (int k = 1; k <= padLen; k++) {
            if (outBuf[outBuf.length - k] != 0) {
                throw new IllegalBlockSizeException("Pad check failed");
            }
        }
        System.arraycopy(outBuf, 0, out, outOfs, outLen);
        return outLen;
    }
}
