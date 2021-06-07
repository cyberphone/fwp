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

import org.webpki.cbor.CBORMap;
import org.webpki.cbor.CBORObject;

/**
 * FWP replying party side assertion support.
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
    
    public FWPAssertionDecoder(byte[] cborData) throws IOException {
        map = CBORObject.decode(cborData).getMap();
        
        // Are we compatible?
        String version = getString(FWPElements.VERSION);
        if (!version.equals(FWPElements.CURRENT_VERSION)) {
            throw new IOException("Received version: " + version + 
                                  " expected: " + FWPElements.CURRENT_VERSION);
        }
        
        // Decode payment request.
        paymentRequest = new PaymentRequest(map.getObject(FWPElements.PAYMENT_REQUEST.cborLabel));
        
        // Host information from the browser.
        hostName = getString(FWPElements.HOST_NAME);
        
        // Check that we didn't forgot anything or that there is other data there as well.
        map.checkObjectForUnread();
    }
}

