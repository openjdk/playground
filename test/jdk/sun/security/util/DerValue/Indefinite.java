/*
 * Copyright (c) 2008, Oracle and/or its affiliates. All rights reserved.
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

/*
 * @test
 * @bug 6731685
 * @summary CertificateFactory.generateCertificates throws IOException on PKCS7 cert chain
 * @modules java.base/sun.security.util
 * @library /test/lib
 */

import java.io.*;
import java.util.Arrays;

import jdk.test.lib.Asserts;
import sun.security.util.*;

public class Indefinite {

    public static void main(String[] args) throws Exception {
        byte[] input = {
            // An OCTET-STRING in 2 parts
            0x24, (byte)0x80, 4, 2, 'a', 'b', 4, 2, 'c', 'd', 0, 0,
        };

        // Add some garbage, may be falsely recognized as EOC
        new DerValue(new ByteArrayInputStream(
                Arrays.copyOf(input, input.length + 4)));

        // Make a SEQUENCE of input and (bool) true.
        byte[] comp = new byte[input.length + 5];
        comp[0] = DerValue.tag_Sequence;
        comp[1] = (byte)(input.length + 3);
        System.arraycopy(input, 0, comp, 2, input.length);
        comp[2 + input.length] = comp[3 + input.length] = comp[4 + input.length] = 1;

        // Read it
        DerValue d = new DerValue(comp);
        Asserts.assertEQ(new String(d.data.getDerValue().getOctetString()), "abcd");
        Asserts.assertTrue(d.data.getBoolean());
        d.data.atEnd();

        // Or skip it
        d = new DerValue(comp);
        d.data.skipDerValue();
        Asserts.assertTrue(d.data.getBoolean());
        d.data.atEnd();
    }
}
