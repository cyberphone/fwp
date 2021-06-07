/*
 *  Copyright 2018-2021 WebPKI.org (http://webpki.org).
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
package org.webpki.webapps.fwp;

import java.io.IOException;

import java.util.HashSet;

import org.webpki.cbor.CBORMap;
import org.webpki.cbor.CBORObject;
import org.webpki.cbor.CBORTextString;

/**
 * FWP client side assertion support.
 */
public class FWPAssertionBuilder {
    
    CBORMap fwpAssertion = new CBORMap();
    
    HashSet<FWPElements> elementList = new HashSet<>();
    
    public FWPAssertionBuilder() throws IOException {
        addStringElement(FWPElements.VERSION, FWPElements.CURRENT_VERSION);
    }
    
    private FWPAssertionBuilder addElement(FWPElements name,
                                           CBORObject value) throws IOException {
        if (!elementList.add(name)) {
            throw new IOException("Duplicate: " + name.toString());
        }
        fwpAssertion.setObject(name.cborLabel, value);
        return this;
    }
    
    private FWPAssertionBuilder addStringElement(FWPElements element,
                                                 String string) throws IOException {
        return addElement(element, new CBORTextString(string));
    }
    
    public FWPAssertionBuilder addPaymentRequest(String jsonString) throws IOException {
        return addElement(FWPElements.PAYMENT_REQUEST,
                          FWPElements.convertPaymentRequest(jsonString));
    }
    
    public FWPAssertionBuilder addHostName(String hostName) throws IOException {
        return addStringElement(FWPElements.HOST_NAME, hostName);
    }
    
    public CBORMap create() throws IOException {
        for (FWPElements name : FWPElements.values()) {
            if (!elementList.contains(name)) {
                throw new IOException("Missing element: " + name.toString());
            }
        }
        return fwpAssertion;
    }
}

