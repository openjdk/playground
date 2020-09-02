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

import java.io.ByteArrayOutputStream;
import java.util.Arrays;
import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;

/**
 * This class acts as the base class for AES KeyWrap algorithms as defined
 * in <a href=https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38F.pdf>
 * "Recommendation for Block Cipher Modes of Operation: Methods for Key Wrapping"
 */
abstract class KeyWrapBaseCipher extends CipherSpi {

    // In NIST SP 800-38F, KWP input size is limited to be no longer
    // than 2^32 bytes. Otherwise, the length cannot be encoded in 32 bits
    // However, given the current spec requirement that recovered text
    // can only be returned after successful tag verification, we are
    // bound by limiting the data size to the size limit of
    // java byte array, e.g. Integer.MAX_VALUE, since all data
    // can only be returned by the doFinal(...) call.
    private static final int MAX_BUF_SIZE = Integer.MAX_VALUE;
    protected static final int BLKSIZE = 16;
    protected static final int SEMI_BLKSIZE = BLKSIZE >> 1;

    private static void checkDataLength(ByteArrayOutputStream buf, int len) {
        if (buf == null) return;
        int buffered = buf.size();
        if (len > MAX_BUF_SIZE - buffered) {
            throw new ProviderException("SunJCE provider only supports " +
                "input size up to " + MAX_BUF_SIZE + " bytes");
        }
    }

    /*
     * Enhanced version of the wrapping function W as defined in section 6.1
     * of NIST SP 800-38F as well as sec 2.2.1 of RFC 3394.
     * Enhanced w/ additional handling as below:
     * - separated out the initial value from the plain text and expanded the
     *   loop for j = 0 separately to minimize data copying
     * - relaxed ptLen requirement and added padding bytes as needed (see the
     *   zeroize code)
     * @param iv the initial value (length: SEMI_BLKSIZE). For KW, iv=ICV1.
     *         For KWP, iv = ICV2 || 32-bit encoding of input length (in bytes).
     * @param pt input bytes
     * @param ptOfs starting offset into the input bytes
     * @param ptLen length of the to-be-wrapped bytes
     * @param out output buffer for the wrapped bytes
     * @param outOfs starting offset for the output buffer
     * @param cipher the initialized cipher object used for the wrapping
     */
    protected static final void W(byte[] iv, byte[] pt, int ptOfs, int ptLen,
            byte[] out, int outOfs, SymmetricCipher cipher) {

        int n = (ptLen + SEMI_BLKSIZE - 1) / SEMI_BLKSIZE;
        //System.out.println("W: inLen = " +  ptLen + ", n = " + n);

        byte[] buffer = new byte[BLKSIZE];

        System.arraycopy(iv, 0, buffer, 0, SEMI_BLKSIZE);
        System.arraycopy(pt, ptOfs, buffer, SEMI_BLKSIZE, SEMI_BLKSIZE);
        //System.out.println("W: copy pt from " + ptOfs + " to " + SEMI_BLKSIZE);

        // for j = 0, use the value from 'iv' and 'pt'
        for (int i = 1; i <= n; i++) {
            int T = i;
            int idx = i<<3;
            cipher.encryptBlock(buffer, 0, buffer, 0);
            // MSB(64, B) xor T
            for (int k = 1; T != 0 && k < 5; k++) {
                byte v = (byte) T;
                buffer[SEMI_BLKSIZE - k] ^= v;
                T >>>= SEMI_BLKSIZE;
            }
            System.arraycopy(buffer, 0, out, outOfs, SEMI_BLKSIZE);
            System.arraycopy(buffer, SEMI_BLKSIZE, out, outOfs + idx,
                    SEMI_BLKSIZE);
            if (i < n) {
                int len = ((i == n-1)? (ptLen - idx): SEMI_BLKSIZE);
                //System.out.println("W: copy pt from " +  (ptOfs + idx) +
                //        " to " + (ptOfs + idx + len));
                System.arraycopy(pt, ptOfs + idx, buffer, SEMI_BLKSIZE, len);
                if (len != SEMI_BLKSIZE) { // need to zeroize the rest
                    Arrays.fill(buffer, SEMI_BLKSIZE + len, BLKSIZE, (byte) 0);
                }
            }
        }

        // for j = 1...5, use the processed value stored into 'out' when
        // j = 0
        for (int j = 1; j < 6; j++) {
            for (int i = 1; i <= n; i++) {
                int T = n*j + i;
                int idx = Math.addExact(outOfs, i<<3);

                System.arraycopy(out, outOfs, buffer, 0, SEMI_BLKSIZE);
                System.arraycopy(out, idx, buffer, SEMI_BLKSIZE, SEMI_BLKSIZE);
                cipher.encryptBlock(buffer, 0, buffer, 0);
                for (int k = 1; T != 0; k++) {
                    byte v = (byte) T;
                    buffer[SEMI_BLKSIZE - k] ^= v;
                    T >>>= SEMI_BLKSIZE;
                }
                System.arraycopy(buffer, 0, out, outOfs, SEMI_BLKSIZE);
                System.arraycopy(buffer, SEMI_BLKSIZE, out, idx, SEMI_BLKSIZE);
            }
        }
    }

    /*
     * Enhanced version of the unwrapping function W^-1 as defined in section
     * 6.1 of NIST SP 800-38F as well as sec 2.2.2 of RFC 3394.
     * Enhanced w/ additional handling as below:
     * - separated out the initial value from the remaining recovered data
     * - since we cannot write out the recovered data until the initial
     *   value and padding bytes are verified. Allocate buffer for the
     *   recovered data and return to the caller instead of accepting output
     *   buffer argument.
     * @param ct input bytes, i.e. the to-be-unwrapped data
     * @param ctOfs starting offset into the input bytes
     * @param ctLen length of the to-be-unwrapped bytes
     * @param ivOut buffer for holding the initial value after unwrapping
     * @param cipher the initialized cipher object used for the wrapping
     */
    protected static final byte[] W_INV(byte[] ct, int ctOfs, int ctLen,
            byte[] ivOut, SymmetricCipher cipher) {

        byte[] buffer = new byte[BLKSIZE];
        System.arraycopy(ct, ctOfs, buffer, 0, SEMI_BLKSIZE);
        byte[] out = Arrays.copyOfRange(ct, ctOfs + SEMI_BLKSIZE,
            ctOfs + ctLen);
        int n = out.length / SEMI_BLKSIZE;

        for (int j = 5; j >= 0; j--) {
            for (int i = n; i > 0; i--) {
                int T = n*j + i;
                int idx = (i-1) << 3;
                System.arraycopy(out, idx, buffer, SEMI_BLKSIZE, SEMI_BLKSIZE);
                for (int k = 1; T != 0; k++) {
                    byte v = (byte) T;
                    buffer[SEMI_BLKSIZE - k] ^= v;
                    T >>>= SEMI_BLKSIZE;
                }
                cipher.decryptBlock(buffer, 0, buffer, 0);
                System.arraycopy(buffer, SEMI_BLKSIZE, out, idx, SEMI_BLKSIZE);
            }
        }
        System.arraycopy(buffer, 0, ivOut, 0, SEMI_BLKSIZE);
        return out;
    }

    abstract protected int implGetOutputSize(int inLen);

    abstract protected int implEncrypt(byte[] in, int inOfs, int inLen,
            byte[] out, int outOfs) throws IllegalBlockSizeException;

    abstract protected int implDecrypt(byte[] in, int inOfs, int inLen,
            byte[] out, int outOfs) throws IllegalBlockSizeException;

    /*
     * internal cipher object which does the real work.
     */
    protected SymmetricCipher cipher;

    /*
     * are we encrypting or decrypting?
     */
    protected boolean decrypting = false;

    /*
     * needed to support oids which associates a fixed key size
     * to the cipher object.
     */
    private final int fixedKeySize; // in bytes, -1 if no restriction
    private final String mode; // null if no restriction
    private final String padding; // null if no restriction
    private final boolean wrapOnly;
    // When wrapOnly == false; input buffering is needed for supporting
    // multi-part encryption/decryption
    private final ByteArrayOutputStream dataBuf;

    /**
     * Creates an instance of KeyWrap cipher using the specified
     * symmetric cipher whose block size must be 128-bit, and
     * the supported mode and padding scheme.
     */
    public KeyWrapBaseCipher(SymmetricCipher cipher, int keySize,
            String mode, String padding) {
        System.out.println("KeyWrapBaseCipher: " + keySize + ", " +
                mode + ", " + padding);
        if (cipher.getBlockSize() != BLKSIZE) {
            throw new ProviderException("Invalid block size for KeyWrap");
        }
        this.cipher = cipher;
        this.fixedKeySize = keySize;
        this.mode = mode;
        this.padding = padding;
        this.wrapOnly = mode.equalsIgnoreCase("ECB");
        this.dataBuf = (wrapOnly? null : new ByteArrayOutputStream());
    }

    /**
     * Sets the mode of this cipher. Must match the mode specified in
     * the constructor.
     *
     * @param mode the cipher mode
     *
     * @exception NoSuchAlgorithmException if the requested cipher mode
     * does not match the supported mode
     */
    @Override
    protected void engineSetMode(String mode)
        throws NoSuchAlgorithmException {
        if (mode != null && !this.mode.equalsIgnoreCase(mode)) {
            throw new NoSuchAlgorithmException(mode + " cannot be used");
        }
    }

    /**
     * Sets the padding mechanism of this cipher. Currently, only
     * "NoPadding" scheme is accepted for this cipher.
     *
     * @param padding the padding mechanism
     *
     * @exception NoSuchPaddingException if the requested padding mechanism
     * does not match the supported padding scheme
     */
    @Override
    protected void engineSetPadding(String padding)
        throws NoSuchPaddingException {
        if (padding != null && !this.padding.equalsIgnoreCase(padding)) {
            throw new NoSuchPaddingException(padding + " cannot be used");
        }
    }

    /**
     * Returns the block size (in bytes). i.e. 16 bytes.
     *
     * @return the block size (in bytes), i.e. 16 bytes.
     */
    @Override
    protected int engineGetBlockSize() {
        return BLKSIZE;
    }

    /**
     * Returns the length in bytes that an output buffer would need to be
     * given the input length <code>inputLen</code> (in bytes).
     *
     * <p>The actual output length of the next <code>update</code> or
     * <code>doFinal</code> call may be smaller than the length returned
     * by this method.
     *
     * @param inputLen the input length (in bytes)
     *
     * @return the required output buffer size (in bytes)
     */
    protected int engineGetOutputSize(int inputLen) {
        int bufferedLen = (dataBuf == null? 0 : dataBuf.size());
        return implGetOutputSize(bufferedLen + inputLen);
    }

    /**
     * Returns the initialization vector (IV) which is null for this cipher.
     *
     * @return null for this cipher.
     */
    @Override
    protected byte[] engineGetIV() {
        return null;
    }

    /**
     * Initializes this cipher with a key and a source of randomness.
     *
     * <p>The cipher only supports the following two operation modes:<b>
     * Cipher.WRAP_MODE, and <b>
     * Cipher.UNWRAP_MODE.
     * <p>For modes other than the above two, UnsupportedOperationException
     * will be thrown.
     *
     * @param opmode the operation mode of this cipher. Only
     * <code>WRAP_MODE</code> or <code>UNWRAP_MODE</code>) are accepted.
     * @param key the secret key.
     * @param random the source of randomness.
     *
     * @exception InvalidKeyException if the given key is inappropriate for
     * initializing this cipher.
     */
    @Override
    protected void engineInit(int opmode, Key key, SecureRandom random)
        throws InvalidKeyException {
        if (wrapOnly &&
            (opmode == Cipher.ENCRYPT_MODE || opmode == Cipher.ENCRYPT_MODE)) {
            throw new UnsupportedOperationException("This cipher can " +
                    "only be used for key wrapping and unwrapping");
        }
        decrypting = (opmode == Cipher.DECRYPT_MODE ||
                opmode == Cipher.UNWRAP_MODE);
        //AESCipher.checkKeySize(key, fixedKeySize);
        //XXX need to add this to SymmetricCipher
        cipher.init(decrypting, key.getAlgorithm(), key.getEncoded());
    }

    /**
     * Initializes this cipher with a key, a set of algorithm parameters,
     * and a source of randomness.
     *
     * <p>The cipher only supports the following two operation modes:<b>
     * Cipher.WRAP_MODE, and <b>
     * Cipher.UNWRAP_MODE.
     * <p>For modes other than the above two, UnsupportedOperationException
     * will be thrown.
     *
     * @param opmode the operation mode of this cipher. Only
     * <code>WRAP_MODE</code> or <code>UNWRAP_MODE</code>) are accepted.
     * @param key the secret key.
     * @param params the algorithm parameters; must be null for this cipher.
     * @param random the source of randomness.
     *
     * @exception InvalidKeyException if the given key is inappropriate for
     * initializing this cipher
     * @exception InvalidAlgorithmParameterException if the given algorithm
     * parameters is not null.
     */
    @Override
    protected void engineInit(int opmode, Key key,
                              AlgorithmParameterSpec params,
                              SecureRandom random)
        throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (params != null) {
            throw new InvalidAlgorithmParameterException("This cipher " +
                "does not accept any parameters");
        }
        engineInit(opmode, key, random);
    }

    /**
     * Initializes this cipher with a key, a set of algorithm parameters,
     * and a source of randomness.
     *
     * <p>The cipher only supports the following two operation modes:<b>
     * Cipher.WRAP_MODE, and <b>
     * Cipher.UNWRAP_MODE.
     * <p>For modes other than the above two, UnsupportedOperationException
     * will be thrown.
     *
     * @param opmode the operation mode of this cipher. Only
     * <code>WRAP_MODE</code> or <code>UNWRAP_MODE</code>) are accepted.
     * @param key the secret key.
     * @param params the algorithm parameters; must be null for this cipher.
     * @param random the source of randomness.
     *
     * @exception InvalidKeyException if the given key is inappropriate.
     * @exception InvalidAlgorithmParameterException if the given algorithm
     * parameters is not null.
     */
    @Override
    protected void engineInit(int opmode, Key key,
                              AlgorithmParameters params,
                              SecureRandom random)
        throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (params != null) {
            throw new InvalidAlgorithmParameterException("This cipher " +
                "does not accept any parameters");
        }
        engineInit(opmode, key, random);
    }

    /**
     * This operation is not supported by this cipher.
     * Since it's impossible to initialize this cipher given the
     * current Cipher.engineInit(...) implementation,
     * IllegalStateException will always be thrown upon invocation.
     *
     * @param in the input buffer.
     * @param inOffset the offset in <code>in</code> where the input
     * starts.
     * @param inLen the input length.
     *
     * @return n/a.
     *
     * @exception IllegalStateException upon invocation of this method.
     */
    @Override
    protected byte[] engineUpdate(byte[] in, int inOffset, int inLen) {
        if (wrapOnly) {
            throw new IllegalStateException("Cipher has not been initialized");
        }
        checkDataLength(dataBuf, inLen);
        dataBuf.write(in, inOffset, inLen);
        return null;
    }

    /**
     * This operation is not supported by this cipher.
     * Since it's impossible to initialize this cipher given the
     * current Cipher.engineInit(...) implementation,
     * IllegalStateException will always be thrown upon invocation.
     *
     * @param in the input buffer.
     * @param inOffset the offset in <code>in</code> where the input
     * starts.
     * @param inLen the input length.
     * @param out the buffer for the result.
     * @param outOffset the offset in <code>out</code> where the result
     * is stored.
     *
     * @return n/a.
     *
     * @exception IllegalStateException upon invocation of this method.
     */
    @Override
    protected int engineUpdate(byte[] in, int inOffset, int inLen,
                               byte[] out, int outOffset)
        throws ShortBufferException {
        if (wrapOnly) {
            throw new IllegalStateException("Cipher has not been initialized");
        }
        checkDataLength(dataBuf, inLen);
        dataBuf.write(in, inOffset, inLen);
        return 0;
    }

    /**
     * This operation is not supported by this cipher.
     * Since it's impossible to initialize this cipher given the
     * current Cipher.engineInit(...) implementation,
     * IllegalStateException will always be thrown upon invocation.
     *
     * @param input the input buffer
     * @param inputOffset the offset in <code>in</code> where the input
     * starts
     * @param inputLen the input length.
     *
     * @return n/a.
     *
     * @exception IllegalStateException upon invocation of this method.
     */
    @Override
    protected byte[] engineDoFinal(byte[] in, int inOfs, int inLen)
        throws IllegalBlockSizeException, BadPaddingException {
        if (wrapOnly) {
            throw new IllegalStateException("Cipher has not been initialized");
        }
        if (dataBuf.size() > 0) {
            if (inLen != 0) {
                checkDataLength(dataBuf, inLen);
                dataBuf.write(in, inOfs, inLen);
            }
            byte[] data = dataBuf.toByteArray();
            in = data;
            inOfs = 0;
            inLen = data.length;
        }
        try {
            byte[] out = new byte[implGetOutputSize(inLen)];
            int outLen = 0;
            if (decrypting) {
                outLen = implDecrypt(in, inOfs, inLen, out, 0);
            } else {
                outLen = implEncrypt(in, inOfs, inLen, out, 0);
            }
            if (outLen < out.length) {
                out = Arrays.copyOf(out, outLen);
            }
            return out;
        } finally {
            dataBuf.reset();
        }
    }

    /**
     * This operation is not supported by this cipher.
     * Since it's impossible to initialize this cipher given the
     * current Cipher.engineInit(...) implementation,
     * IllegalStateException will always be thrown upon invocation.
     *
     * @param in the input buffer.
     * @param inOffset the offset in <code>in</code> where the input
     * starts.
     * @param inLen the input length.
     * @param out the buffer for the result.
     * @param outOffset the ofset in <code>out</code> where the result
     * is stored.
     *
     * @return n/a.
     *
     * @exception IllegalStateException upon invocation of this method.
     */
    protected int engineDoFinal(byte[] in, int inOfs, int inLen,
                                byte[] out, int outOfs)
        throws IllegalBlockSizeException, ShortBufferException,
               BadPaddingException {
        if (wrapOnly) {
            throw new IllegalStateException("Cipher has not been initialized");
        }
        if (dataBuf.size() > 0) {
            if (inLen != 0) {
                checkDataLength(dataBuf, inLen);
                dataBuf.write(in, inOfs, inLen);
            }
            byte[] data = dataBuf.toByteArray();
            in = data;
            inOfs = 0;
            inLen = data.length;
        }
        int estOutLen = implGetOutputSize(inLen);
        if (out.length - outOfs < estOutLen) {
            throw new ShortBufferException("Need at least " + estOutLen);
        }
        try {
            int outLen = 0;
            byte[] out2 = new byte[estOutLen];
            if (decrypting) {
                outLen = implDecrypt(in, inOfs, inLen, out2, 0);
            } else {
                outLen = implEncrypt(in, inOfs, inLen, out2, 0);
            }
            // can only write out the result after verification succeeds
            System.arraycopy(out2, 0, out, outOfs, outLen);
            return outLen;
        } finally {
            dataBuf.reset();
        }

    }

    /**
     * Returns the parameters used with this cipher which is always null
     * for this cipher.
     *
     * @return null since this cipher does not use any parameters.
     */
    @Override
    protected AlgorithmParameters engineGetParameters() {
        return null;
    }

    /**
     * Returns the key size of the given key object in number of bits.
     *
     * @param key the key object.
     *
     * @return the "effective" key size of the given key object.
     *
     * @exception InvalidKeyException if <code>key</code> is invalid.
     */
    protected int engineGetKeySize(Key key) throws InvalidKeyException {
        byte[] encoded = key.getEncoded();
        if ((cipher instanceof AESCrypt) &&
            !AESCrypt.isKeySizeValid(encoded.length)) {
            throw new InvalidKeyException("Invalid key length: " +
                                          encoded.length + " bytes");
        }
        return Math.multiplyExact(encoded.length, 8);
    }

    /**
     * Wrap a key.
     *
     * @param key the key to be wrapped.
     *
     * @return the wrapped key.
     *
     * @exception IllegalBlockSizeException if this cipher is a block
     * cipher, no padding has been requested, and the length of the
     * encoding of the key to be wrapped is not a
     * multiple of the block size.
     *
     * @exception InvalidKeyException if it is impossible or unsafe to
     * wrap the key with this cipher (e.g., a hardware protected key is
     * being passed to a software only cipher).
     */
    @Override
    protected byte[] engineWrap(Key key)
            throws IllegalBlockSizeException, InvalidKeyException {

        byte[] keyVal = key.getEncoded();
        if ((keyVal == null) || (keyVal.length == 0)) {
            throw new InvalidKeyException("Cannot get an encoding of " +
                                          "the key to be wrapped");
        }

        int keyValLen = keyVal.length;
        int outLen = implGetOutputSize(keyValLen);
        byte[] out = new byte[outLen];
        outLen = implEncrypt(keyVal, 0, keyValLen, out, 0);
        if (outLen < out.length) {
            out = Arrays.copyOf(out, outLen);
        }
        return out;

    }

    /**
     * Unwrap a previously wrapped key.
     *
     * @param wrappedKey the key to be unwrapped.
     *
     * @param wrappedKeyAlgorithm the algorithm the wrapped key is for.
     *
     * @param wrappedKeyType the type of the wrapped key.
     * This is one of <code>Cipher.SECRET_KEY</code>,
     * <code>Cipher.PRIVATE_KEY</code>, or <code>Cipher.PUBLIC_KEY</code>.
     *
     * @return the unwrapped key.
     *
     * @exception NoSuchAlgorithmException if no installed providers
     * can create keys of type <code>wrappedKeyType</code> for the
     * <code>wrappedKeyAlgorithm</code>.
     *
     * @exception InvalidKeyException if <code>wrappedKey</code> does not
     * represent a wrapped key of type <code>wrappedKeyType</code> for
     * the <code>wrappedKeyAlgorithm</code>.
     */
    @Override
    protected Key engineUnwrap(byte[] wrappedKey,
            String wrappedKeyAlgorithm, int wrappedKeyType)
            throws InvalidKeyException, NoSuchAlgorithmException {
        int wrappedKeyLen = wrappedKey.length;
        // ensure the wrappedKey length is multiples of SEMI_BLKSIZE and
        // non-zero
        if (wrappedKeyLen == 0) {
            throw new InvalidKeyException("The wrapped key is empty");
        }

        int outLen = implGetOutputSize(wrappedKeyLen);
        byte[] out = new byte[outLen];
        try {
            outLen = implDecrypt(wrappedKey, 0, wrappedKeyLen, out, 0);
        } catch (IllegalBlockSizeException e) {
            throw new InvalidKeyException(e);
        }
        if (outLen < out.length) {
            out = Arrays.copyOf(out, outLen);
        }
        return ConstructKeys.constructKey(out, wrappedKeyAlgorithm,
                wrappedKeyType);
    }
}
