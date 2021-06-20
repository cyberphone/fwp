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

import org.webpki.fwp.FWPCrypto.FWPPreSigner;

import org.webpki.util.ISODateTime;

/**
 * FWP client side assertion support.
 */
public class FWPAssertionBuilder {
    
    CBORMap fwpAssertion = new CBORMap();
    
    HashSet<FWPElements> elementList = new HashSet<>();
    
    public FWPAssertionBuilder() throws IOException {
        setStringElement(FWPElements.FWP_VERSION, FWPElements.CURRENT_VERSION);
    }
    
    private FWPAssertionBuilder setElement(FWPElements name,
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
    
    private FWPAssertionBuilder setStringElement(FWPElements element,
                                                 String string) throws IOException {
        return setElement(element, new CBORTextString(string));
    }
    
    public FWPAssertionBuilder setPaymentRequest(FWPPaymentRequest jsonPaymentRequest)
            throws IOException {
        return setElement(FWPElements.PAYMENT_REQUEST, jsonPaymentRequest.serializeAsCBOR());
    }
    
    public FWPAssertionBuilder setPayeeHost(String payeeHost) throws IOException {
        return setStringElement(FWPElements.PAYEE_HOST, payeeHost);
    }
    
    private CBORMap nameVersion(String name, String version) throws IOException {
        return new CBORMap().setObject(FWPElements.CBOR_PDSUB_NAME,
                                       new CBORTextString(name))
                            .setObject(FWPElements.CBOR_PDSUB_VERSION,
                                       new CBORTextString(version));
    }
    
    public FWPAssertionBuilder setPlatformData(String osName,
                                               String osVersion,
                                               String browserName,
                                               String browserVersion) throws IOException {
        return setElement(FWPElements.PLATFORM_DATA,
                          new CBORMap().setObject(FWPElements.CBOR_PD_OPERATING_SYSTEM,
                                                  nameVersion(osName, osVersion))
                                       .setObject(FWPElements.CBOR_PD_USER_AGENT,
                                                  nameVersion(browserName, browserVersion)));
    }
    
    public FWPAssertionBuilder setAccountData(String accountId,
                                              String serialNumber,
                                              String paymentMethod) throws IOException {
        setStringElement(FWPElements.ACCOUNT_ID, accountId);
        setStringElement(FWPElements.SERIAL_NUMBER, serialNumber);
        setStringElement(FWPElements.PAYMENT_METHOD, paymentMethod);
        return this;
    }
    
    public FWPAssertionBuilder setOptionalTimeStamp(GregorianCalendar timeStamp) throws IOException {
        return setElement(FWPElements.TIME_STAMP,
                          new CBORDateTime(timeStamp, ISODateTime.LOCAL_NO_SUBSECONDS));
    }
    
    public FWPAssertionBuilder setOptionalNetworkData(String jsonStringOrNull) throws IOException {
        return jsonStringOrNull == null ? this : setElement(FWPElements.NETWORK_DATA,
                                                            JSONReader.convert(jsonStringOrNull));
    }

    public FWPAssertionBuilder setUserAuthorizationMethod(
                          FWPElements.UserAuthorizationMethods userAuthz) throws IOException {
        return setElement(FWPElements.USER_AUTHORIZATION_METHOD,
                          new CBORInteger(userAuthz.cborValue));
    }

    public byte[] create(FWPPreSigner fwpPreSigner) throws IOException, GeneralSecurityException {
        // Default time is now.
        if (!elementList.contains(FWPElements.TIME_STAMP)) {
            setOptionalTimeStamp(new GregorianCalendar());
        }
        for (FWPElements name : FWPElements.values()) {
            // Only NETWORK_DATA is optional.
            if (!elementList.contains(name) &&
                name != FWPElements.NETWORK_DATA &&
                name != FWPElements.AUTHORIZATION) {
                throw new IOException("Missing element: " + name.toString());
            }
        }
        setElement(FWPElements.AUTHORIZATION, fwpPreSigner.appendSignatureObject());
        return fwpAssertion.encode();
    }
}

