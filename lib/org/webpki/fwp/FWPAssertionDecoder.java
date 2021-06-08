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

import org.webpki.cbor.CBORMap;
import org.webpki.cbor.CBORObject;

/**
 * FWP relying party side assertion support.
 */
public class FWPAssertionDecoder {

    CBORMap cborPaymentRequest;

    public class PaymentRequest {
        
        String getString(int cborId) throws IOException {
            return cborPaymentRequest.getObject(cborId).getTextString();
        }

        PaymentRequest(CBORObject cborObject) throws IOException {
            cborPaymentRequest = cborObject.getMap();
            payee = getString(FWPElements.CBOR_PR_PAYEE);
            id = getString(FWPElements.CBOR_PR_ID);
            amount = getString(FWPElements.CBOR_PR_AMOUNT);
            currency = getString(FWPElements.CBOR_PR_CURRENCY);
        }
        
        String payee;
        public String getPayee() {
            return payee;
        }
        
        String id;
        public String getId() {
            return id;
        }
        
        String amount;
        public String getAmount() {
            return amount;
        }

        String currency;
        public String getCurrency() {
            return currency;
        }

    }
    
    PaymentRequest paymentRequest;
    public PaymentRequest getPaymentRequest() {
        return paymentRequest;
    }
    
    String hostName;
    public String getHostName() {
        return hostName;
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

    CBORMap map;
  
    public void verifyClaimedPaymentRequest(String jsonString) throws IOException {
        CBORMap claimedPaymentRequest = FWPElements.convertPaymentRequest(jsonString);
        if (!cborPaymentRequest.equals(claimedPaymentRequest)) {
            throw new IOException("Claimed:\n" + claimedPaymentRequest.toString() +
                                  "Actual:\n" + cborPaymentRequest.toString());
        }
    }
    
    String getString(FWPElements name) throws IOException {
        return map.getObject(name.cborLabel).getTextString();
    }
    
    public CBORMap getDecoded() {
        return map;
    }
    
    public FWPAssertionDecoder(byte[] signedFwpAssertion) throws IOException {
        map = CBORObject.decode(signedFwpAssertion).getMap();
        
        // Are we compatible?
        String version = getString(FWPElements.FWP_VERSION);
        if (!version.equals(FWPElements.CURRENT_VERSION)) {
            throw new IOException("Received version: " + version + 
                                  " expected: " + FWPElements.CURRENT_VERSION);
        }
        
        // Decode Payment Request.
        paymentRequest = new PaymentRequest(map.getObject(FWPElements.PAYMENT_REQUEST.cborLabel));
        
        // Account data.
        accountId = getString(FWPElements.ACCOUNT_ID);
        serialNumber = getString(FWPElements.SERIAL_NUMBER);
        paymentMethod = getString(FWPElements.PAYMENT_METHOD);
        
        // Platform Data
        CBORMap platformData = map.getObject(FWPElements.PLATFORM_DATA.cborLabel).getMap();
        platformData.scan();
        
        // User Authorization Method
        map.getObject(FWPElements.USER_AUTHORIZATION_METHOD.cborLabel).scan();
        
        // Date Time
        map.getObject(FWPElements.TIME_STAMP.cborLabel).scan();

        // Host information from the browser.
        hostName = getString(FWPElements.PAYEE_HOST_NAME);
        
        // Optional Network Data.
        if (map.hasKey(FWPElements.NETWORK_DATA.cborLabel)) {
            map.getObject(FWPElements.NETWORK_DATA.cborLabel).scan();
        }
        
        // Check that we didn't forgot anything or that there is other data there as well.
        map.checkObjectForUnread();
    }
}

