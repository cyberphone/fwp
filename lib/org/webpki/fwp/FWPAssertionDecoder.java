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

import org.webpki.cbor.CBORArray;
import org.webpki.cbor.CBORMap;
import org.webpki.cbor.CBORObject;

import org.webpki.util.ISODateTime;

/**
 * FWP relying party side assertion (SAD) support.
 */
public class FWPAssertionDecoder {
    
    private CBORMap fwpAssertion;
    
    public class PlatformNameVersion {
        String name;
        String version;
        
        public String getName() {
            return name;
        }
        
        public String getVersion() {
            return version;
        }
        
        PlatformNameVersion(CBORObject nameVersion) {
            this.name = nameVersion.getMap().get(FWPElements.CBOR_PDSUB_NAME).getString();
            this.version = nameVersion.getMap().get(FWPElements.CBOR_PDSUB_VERSION).getString();
        }
    }
    
    private PlatformNameVersion operatingSystem;
    public PlatformNameVersion getOperatingSystem() {
        return operatingSystem;
    }
    
    private PlatformNameVersion userAgent;
    public PlatformNameVersion getUserAgent() {
        return userAgent;
    }

    private GregorianCalendar timeStamp;
    public GregorianCalendar getTimeStamp() {
        return timeStamp;
    }
    
    private CBORObject networkOptions;
    public CBORObject getnetworkOptions() {
        return networkOptions;
    }
    
    private FWPPaymentRequest paymentRequest;
    public FWPPaymentRequest getPaymentRequest() {
        return paymentRequest;
    }
    
    private String payeeHost;
    public String getPayeeHost() {
        return payeeHost;
    }
    
    private String accountId;
    public String getAccountId() {
        return accountId;
    }

    private String serialNumber;
    public String getSerialNumber() {
        return serialNumber;
    }

    private String paymentNetwork;
    public String getPaymentNetwork() {
        return paymentNetwork;
    }

    private double[] location;
    public double[] getLocation() {
        return location;
    }

    public void verifyClaimedPaymentRequest(FWPPaymentRequest claimedPaymentRequest) {
        if (!paymentRequest.equals(claimedPaymentRequest)) {
            throw new FWPException("Claimed:\n" + claimedPaymentRequest.toString() +
                                      "Actual:\n" + paymentRequest.toString());
        }
    }
    
    private String getString(FWPElements name) {
        return fwpAssertion.get(name.cborLabel).getString();
    }
    
    private byte[] publicKey;
    public byte[] getPublicKey() {
        return publicKey;
    }
    
    private HashSet<FWPCrypto.UserValidation> userValidation = new HashSet<>();
    public HashSet<FWPCrypto.UserValidation> getUserValidation() {
        return userValidation;
    }
    
    public FWPAssertionDecoder(byte[] signedFwpAssertion) {
        // Convert SAD binary into CBOR objects.
        this(CBORObject.decode(signedFwpAssertion).getMap());
    }
        
    public FWPAssertionDecoder(CBORMap signedFwpAssertion) {
        fwpAssertion = signedFwpAssertion;
        
        // Payment Request (PRCD)
        paymentRequest = new FWPPaymentRequest(
                fwpAssertion.get(FWPElements.PAYMENT_REQUEST.cborLabel));

        // Account.
        accountId = getString(FWPElements.ACCOUNT_ID);
        
        // For usage with the following payment network.
        paymentNetwork = getString(FWPElements.PAYMENT_NETWORK_ID);

        // Serial number of payment credential. Note: this is unrelated to the
        // FIDO "credentialId" (which only used locally by the wallet).
        serialNumber = getString(FWPElements.SERIAL_NUMBER);

        // Platform Data
        CBORMap platformData = fwpAssertion.get(
                FWPElements.PLATFORM_DATA.cborLabel).getMap();
        operatingSystem = new PlatformNameVersion(
                platformData.get(FWPElements.CBOR_PD_OPERATING_SYSTEM));
        userAgent = new PlatformNameVersion(
                platformData.get(FWPElements.CBOR_PD_USER_AGENT));

        // Time Stamp
        timeStamp = ISODateTime.decode(getString(FWPElements.TIME_STAMP),
                                       ISODateTime.COMPLETE);

        // Payee Host information from the browser
        payeeHost = getString(FWPElements.PAYEE_HOST);

        // Optional Network Data.
        if (fwpAssertion.containsKey(FWPElements.NETWORK_OPTIONS.cborLabel)) {
            // There is such data, get it!  It can be any CBOR data
            // that has a 1-2-1 translation to JSON.
            networkOptions = fwpAssertion.get(FWPElements.NETWORK_OPTIONS.cborLabel);
            // We mark it as "read" to not get a problem with checkForUnread().
            networkOptions.scan();
        }

        // Optional location.
        if (fwpAssertion.containsKey(FWPElements.LOCATION.cborLabel)) {
            // There is a location, get it!
            CBORArray cborLocation = 
                    fwpAssertion.get(FWPElements.LOCATION.cborLabel).getArray();
            location = new double[2];
            for (int i = 0; i < 2; i++) {
                location[i] = cborLocation.get(i).getDouble();
            }
        }
        
        // Finally, the authorization signature.
        // Note: this must be the last step since it modifies the fwpAssertion.
        publicKey = FWPCrypto.validateFwpSignature(fwpAssertion, userValidation);

        // Check that we didn't forgot anything or that there is "other" data.
        fwpAssertion.checkForUnread();
    }
}

