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
package org.webpki.fwp;

import java.io.IOException;

import java.security.GeneralSecurityException;

import java.util.GregorianCalendar;
import java.util.HashSet;

import org.webpki.cbor.CBORDateTime;
import org.webpki.cbor.CBORInteger;
import org.webpki.cbor.CBORMap;
import org.webpki.cbor.CBORObject;
import org.webpki.cbor.CBORTextString;
import org.webpki.cbor.JSONReader;

import org.webpki.fwp.FWPCrypto.FWPSigner;

import org.webpki.util.ISODateTime;

/**
 * FWP client side assertion support.
 */
public class FWPAssertionBuilder {
    
    CBORMap fwpAssertion = new CBORMap();
    
    HashSet<FWPElements> elementList = new HashSet<>();
    
    public FWPAssertionBuilder() throws IOException {
        addStringElement(FWPElements.FWP_VERSION, FWPElements.CURRENT_VERSION);
    }
    
    private FWPAssertionBuilder addElement(FWPElements name,
                                           CBORObject value) throws IOException {
        if (elementList.contains(FWPElements.AUTHORIZATION)) {
        	throw new IOException("Nothing can be added after: " + 
                                  FWPElements.AUTHORIZATION.toString());
        }
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
    
    public FWPAssertionBuilder addPayeeHostName(String payeeHostName) throws IOException {
        return addStringElement(FWPElements.PAYEE_HOST_NAME, payeeHostName);
    }
    
    private CBORMap nameVersion(String name, String version) throws IOException {
        return new CBORMap().setObject(FWPElements.CBOR_PDSUB_NAME,
                                       new CBORTextString(name))
                            .setObject(FWPElements.CBOR_PDSUB_VERSION,
                                       new CBORTextString(version));
    }
    
    public FWPAssertionBuilder addPlatformData(String osName,
                                               String osVersion,
                                               String browserName,
                                               String browserVersion) throws IOException {
        return addElement(FWPElements.PLATFORM_DATA,
                          new CBORMap().setObject(FWPElements.CBOR_PD_OPERATING_SYSTEM,
                                                  nameVersion(osName, osVersion))
                                       .setObject(FWPElements.CBOR_PD_USER_AGENT,
                                                  nameVersion(browserName, browserVersion)));
    }
    
    public FWPAssertionBuilder addAccountData(String accountId,
                                              String serialNumber,
                                              String paymentMethod) throws IOException {
        addStringElement(FWPElements.ACCOUNT_ID, accountId);
        addStringElement(FWPElements.SERIAL_NUMBER, serialNumber);
        addStringElement(FWPElements.PAYMENT_METHOD, paymentMethod);
        return this;
    }
    
    public FWPAssertionBuilder addOptionalTimeStamp(GregorianCalendar timeStamp) throws IOException {
        return addElement(FWPElements.TIME_STAMP,
                          new CBORDateTime(timeStamp, ISODateTime.LOCAL_NO_SUBSECONDS));
    }
    
    public FWPAssertionBuilder addOptionalNetworkData(String jsonStringOrNull) throws IOException {
        return jsonStringOrNull == null ? this : addElement(FWPElements.NETWORK_DATA,
                                                            JSONReader.convert(jsonStringOrNull));
    }

    public FWPAssertionBuilder addUserAuthorizationMethod(
                          FWPElements.UserAuthorizationMethods userAuthz) throws IOException {
        return addElement(FWPElements.USER_AUTHORIZATION_METHOD,
                          new CBORInteger(userAuthz.ordinal()));
    }

    public byte[] create(FWPSigner fwpSigner) throws IOException, GeneralSecurityException {
        // Default time is now.
        if (!elementList.contains(FWPElements.TIME_STAMP)) {
            addOptionalTimeStamp(new GregorianCalendar());
        }
        for (FWPElements name : FWPElements.values()) {
            // Only NETWORK_DATA is optional.
            if (!elementList.contains(name) &&
                name != FWPElements.NETWORK_DATA &&
                name != FWPElements.AUTHORIZATION) {
                throw new IOException("Missing element: " + name.toString());
            }
        }
        elementList.add(FWPElements.AUTHORIZATION);
        return fwpSigner.appendSignatureObject(fwpAssertion,
        		                               FWPElements.AUTHORIZATION.cborLabel).encode();
    }
}

