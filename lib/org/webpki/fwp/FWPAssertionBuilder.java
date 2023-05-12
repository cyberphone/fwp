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

import java.util.GregorianCalendar;
import java.util.HashSet;

import org.webpki.cbor.CBORMap;
import org.webpki.cbor.CBORObject;
import org.webpki.cbor.CBORString;
import org.webpki.cbor.CBORArray;
import org.webpki.cbor.CBORFloat;
import org.webpki.cbor.CBORFromJSON;

import org.webpki.fwp.FWPCrypto.FWPPreSigner;

import org.webpki.util.ISODateTime;

/**
 * FWP client side assertion (AD) support.
 */
public class FWPAssertionBuilder {
    
    CBORMap fwpAssertion = new CBORMap();

    HashSet<FWPElements> elementList = new HashSet<>();

    private FWPAssertionBuilder setElement(FWPElements name, CBORObject value) {
        if (!elementList.add(name)) {
            throw new FWPException("Duplicate: " + name.toString());
        }
        fwpAssertion.set(name.cborLabel, value);
        return this;
    }

    private FWPAssertionBuilder setStringElement(FWPElements element, String string) {
        return setElement(element, new CBORString(string));
    }

    private CBORMap nameVersion(String name, String version) {
        return new CBORMap().set(FWPElements.CBOR_PDSUB_NAME, new CBORString(name))
                            .set(FWPElements.CBOR_PDSUB_VERSION, new CBORString(version));
    }

    public FWPAssertionBuilder setPaymentRequest(FWPPaymentRequest jsonPaymentRequest) {
        return setElement(FWPElements.PAYMENT_REQUEST, jsonPaymentRequest.serializeAsCBOR());
    }
    
    public FWPAssertionBuilder setPayeeHost(String payeeHost) {
        return setStringElement(FWPElements.PAYEE_HOST, payeeHost);
    }
    
    public FWPAssertionBuilder setPlatformData(String osName,
                                               String osVersion,
                                               String browserName,
                                               String browserVersion) {
        return setElement(FWPElements.PLATFORM_DATA,
                          new CBORMap().set(FWPElements.CBOR_PD_OPERATING_SYSTEM,
                                            nameVersion(osName, osVersion))
                                       .set(FWPElements.CBOR_PD_USER_AGENT,
                                            nameVersion(browserName, browserVersion)));
    }
    
    public FWPAssertionBuilder setPaymentInstrumentData(String accountId,
                                                        String serialNumber,
                                                        String paymentNetworkId) {
        setStringElement(FWPElements.ACCOUNT_ID, accountId);
        setStringElement(FWPElements.SERIAL_NUMBER, serialNumber);
        setStringElement(FWPElements.PAYMENT_NETWORK_ID, paymentNetworkId);
        return this;
    }

    public FWPAssertionBuilder setLocation(double latitude, double longitude) {
        setElement(FWPElements.LOCATION, 
                   new CBORArray()
                       .add(new CBORFloat(latitude))
                       .add(new CBORFloat(longitude)));
        return this;
    }

    public FWPAssertionBuilder setOptionalTimeStamp(GregorianCalendar timeStamp) {
        return setElement(FWPElements.TIME_STAMP,
                          new CBORString(ISODateTime.encode(timeStamp, 
                                                            ISODateTime.LOCAL_NO_SUBSECONDS)));
    }

    public FWPAssertionBuilder setNetworkOptions(String jsonStringOrNull) {
        return jsonStringOrNull == null ? this : 
            setElement(FWPElements.NETWORK_OPTIONS, CBORFromJSON.convert(jsonStringOrNull));
    }

    public byte[] create(FWPPreSigner fwpPreSigner) {
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
                throw new FWPException("Missing element: " + name.toString());
            }
        }
        // Attempts rebuilding will return NPE.
        elementList = null;
        return fwpAssertion.encode();
    }
}

