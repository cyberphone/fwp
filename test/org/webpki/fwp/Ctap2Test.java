/*
 *  Copyright 2006-2021 WebPKI.org (http://webpki.org).
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */
package org.webpki.fwp;

import java.io.IOException;

import java.util.Base64;

import org.webpki.cbor.CBORObject;


/**
 * Test externally generated Ctap2 data.
 */
public class Ctap2Test {
    
    static byte[] base64UrlDecode(String b64u) {
        return Base64.getUrlDecoder().decode(b64u);
    }
    
    public static void main(String[] args) {
        try {
            if (args.length != 3) {
                throw new IOException("Wrong number of parameters");
            }
            byte[] sadObject = FWPCrypto.addSignature(base64UrlDecode(args[0]), 
                                                      null, // CTAP2 mode
                                                      base64UrlDecode(args[2]), 
                                                      base64UrlDecode(args[1]));
            new FWPAssertionDecoder(sadObject);
            System.out.println(CBORObject.decode(sadObject).toString());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
