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

import org.webpki.cbor.CBORMap;
import org.webpki.cbor.CBORObject;
import org.webpki.cbor.CBORString;
import org.webpki.cbor.CBORArray;
import org.webpki.cbor.CBORDouble;
import org.webpki.cbor.CBORFromJSON;

import org.webpki.fwp.FWPCrypto.FWPPreSigner;

import org.webpki.util.ISODateTime;

/**
 * FWP client side assertion (AD) support.
 */
public class FWPAssertionBuilder {
    
    CBORMap fwpAssertion = new CBORMap();

    HashSet<FWPElements> elementList = new HashSet<>();

    private FWPAssertionBuilder setElement(FWPElements name, 
                                           CBORObject value) throws IOException {
        if (!elementList.add(name)) {
            throw new IOException("Duplicate: " + name.toString());
        }
        fwpAssertion.setObject(name.cborLabel, value);
        return this;
    }

    private FWPAssertionBuilder setStringElement(FWPElements element,
                                                 String string) throws IOException {
        return setElement(element, new CBORString(string));
    }

    private CBORMap nameVersion(String name, String version) throws IOException {
        return new CBORMap().setObject(FWPElements.CBOR_PDSUB_NAME,
                                       new CBORString(name))
                            .setObject(FWPElements.CBOR_PDSUB_VERSION,
                                       new CBORString(version));
    }

    public FWPAssertionBuilder setPaymentRequest(FWPPaymentRequest jsonPaymentRequest)
            throws IOException {
        return setElement(FWPElements.PAYMENT_REQUEST, jsonPaymentRequest.serializeAsCBOR());
    }
    
    public FWPAssertionBuilder setPayeeHost(String payeeHost) throws IOException {
        return setStringElement(FWPElements.PAYEE_HOST, payeeHost);
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
    
    public FWPAssertionBuilder setPaymentInstrumentData(String accountId,
                                                        String serialNumber,
                                                        String paymentNetworkId) 
            throws IOException {
        setStringElement(FWPElements.ACCOUNT_ID, accountId);
        setStringElement(FWPElements.SERIAL_NUMBER, serialNumber);
        setStringElement(FWPElements.PAYMENT_NETWORK_ID, paymentNetworkId);
        return this;
    }

    public FWPAssertionBuilder setLocation(double latitude, double longitude) 
            throws IOException {
        setElement(FWPElements.LOCATION, 
                   new CBORArray()
                       .addObject(new CBORDouble(latitude))
                       .addObject(new CBORDouble(longitude)));
        return this;
    }

    public FWPAssertionBuilder setOptionalTimeStamp(GregorianCalendar timeStamp) 
            throws IOException {
        return setElement(FWPElements.TIME_STAMP,
                          new CBORString(ISODateTime.formatDateTime(
                                  timeStamp, ISODateTime.LOCAL_NO_SUBSECONDS)));
    }

    public FWPAssertionBuilder setNetworkOptions(String jsonStringOrNull) throws IOException {
        return jsonStringOrNull == null ? this : setElement(FWPElements.NETWORK_OPTIONS,
                                                            CBORFromJSON.convert(jsonStringOrNull));
    }

    public byte[] create(FWPPreSigner fwpPreSigner) throws IOException, GeneralSecurityException {
        // Default time is now.
        if (!elementList.contains(FWPElements.TIME_STAMP)) {
            setOptionalTimeStamp(new GregorianCalendar());
        }
        setElement(FWPElements.AUTHORIZATION, fwpPreSigner.appendSignatureObject());
        for (FWPElements name : FWPElements.values()) {
            // NETWORK_DATA and LOCATION are optional.
            if (!elementList.contains(name) &&
                name != FWPElements.NETWORK_OPTIONS &&
                name != FWPElements.LOCATION) {
                throw new IOException("Missing element: " + name.toString());
            }
        }
        // Attempts rebuilding will return NPE.
        elementList = null;
        return fwpAssertion.encode();
    }
}

