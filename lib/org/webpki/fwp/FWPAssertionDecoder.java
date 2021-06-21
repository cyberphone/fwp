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

import org.webpki.cbor.CBORMap;
import org.webpki.cbor.CBORObject;

/**
 * FWP relying party side assertion support.
 */
public class FWPAssertionDecoder {
    
    public class PlatformNameVersion {
        String name;
        String version;
        
        public String getName() {
            return name;
        }
        
        public String getVersion() {
            return version;
        }
        
        PlatformNameVersion(CBORObject nameVersion) throws IOException {
            this.name = nameVersion.getMap().getObject(
                    FWPElements.CBOR_PDSUB_NAME).getTextString();
            this.version = nameVersion.getMap().getObject(
                    FWPElements.CBOR_PDSUB_VERSION).getTextString();
        }
    }
    
    PlatformNameVersion operatingSystem;
    public PlatformNameVersion getOperatingSystem() {
        return operatingSystem;
    }
    
    PlatformNameVersion userAgent;
    public PlatformNameVersion getUserAgent() {
        return userAgent;
    }

    GregorianCalendar timeStamp;
    public GregorianCalendar getTimeStamp() {
        return timeStamp;
    }
    
    FWPElements.UserAuthorizationMethods userAuthorizationMethod;
    public FWPElements.UserAuthorizationMethods getUserAuthorizationMethod() {
        return userAuthorizationMethod;
    }
    
    CBORObject networkData;
    public CBORObject getNetworkData() {
        return networkData;
    }
    
    FWPPaymentRequest paymentRequest;
    public FWPPaymentRequest getPaymentRequest() {
        return paymentRequest;
    }
    
    String payeeHost;
    public String getPayeeHost() {
        return payeeHost;
    }
    
    String accountId;
    public String getAccountId() {
        return accountId;
    }

    String serialNumber;
    public String getSerialNumber() {
        return serialNumber;
    }

    String paymentMethod;
    public String getPaymentMethod() {
        return paymentMethod;
    } 

    CBORMap fwpAssertion;
  
    public void verifyClaimedPaymentRequest(FWPPaymentRequest claimedPaymentRequest) 
            throws IOException {
        if (!paymentRequest.equals(claimedPaymentRequest)) {
            throw new IOException("Claimed:\n" + claimedPaymentRequest.toString() +
                                  "Actual:\n" + paymentRequest.toString());
        }
    }
    
    String getString(FWPElements name) throws IOException {
        return fwpAssertion.getObject(name.cborLabel).getTextString();
    }
    
    public CBORMap getDecoded() {
        return fwpAssertion;
    }
    
    byte[] publicKey;
    public byte[] getPublicKey() {
        return publicKey;
    }
    
    public FWPAssertionDecoder(byte[] signedFwpAssertion) throws IOException,
                                                                 GeneralSecurityException {
        // Convert binary into CBOR objects.
        fwpAssertion = CBORObject.decode(signedFwpAssertion).getMap();
        
        // Are we compatible?
        String version = getString(FWPElements.FWP_VERSION);
        if (!version.equals(FWPElements.CURRENT_VERSION)) {
            throw new IOException("Received version: " + version + 
                                  " expected: " + FWPElements.CURRENT_VERSION);
        }

        // Payment Request (PRCD)
        paymentRequest = new FWPPaymentRequest(
                fwpAssertion.getObject(FWPElements.PAYMENT_REQUEST.cborLabel));

        // Account.
        accountId = getString(FWPElements.ACCOUNT_ID);
        
        // For usage with the following payment method.
        paymentMethod = getString(FWPElements.PAYMENT_METHOD);

        // Serial number of payment credential. Note: this is unrelated to FIDO credential Id.
        serialNumber = getString(FWPElements.SERIAL_NUMBER);

        // Platform Data
        CBORMap platformData = fwpAssertion.getObject(
                FWPElements.PLATFORM_DATA.cborLabel).getMap();
        operatingSystem = new PlatformNameVersion(
                platformData.getObject(FWPElements.CBOR_PD_OPERATING_SYSTEM));
        userAgent = new PlatformNameVersion(
                platformData.getObject(FWPElements.CBOR_PD_USER_AGENT));

        // User Authorization Method
        userAuthorizationMethod = FWPElements.getUserAuthorizationMethod(fwpAssertion.getObject(
                FWPElements.USER_AUTHORIZATION_METHOD.cborLabel).getInt());
        
        // Date Time
        timeStamp = fwpAssertion.getObject(FWPElements.TIME_STAMP.cborLabel).getDateTime();

        // Host information from the browser
        payeeHost = getString(FWPElements.PAYEE_HOST);

        // Optional Network Data.
        if (fwpAssertion.hasKey(FWPElements.NETWORK_DATA.cborLabel)) {
            // There is such data, get it!  It can be any CBOR data
            // that has a 1-2-1 translation to JSON.
            networkData = fwpAssertion.getObject(FWPElements.NETWORK_DATA.cborLabel);
            // We mark it as "read" to not get a problem with checkObjectForUnread().
            networkData.scan();
        }

        // Finally, the authorization signature.
        publicKey = FWPCrypto.validateFwpSignature(fwpAssertion);

        // Check that we didn't forgot anything or that there is "other" data.
        fwpAssertion.checkForUnread();
    }
}

