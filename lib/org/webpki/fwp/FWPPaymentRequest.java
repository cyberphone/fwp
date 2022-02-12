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

import org.webpki.cbor.CBORInteger;
import org.webpki.cbor.CBORMap;
import org.webpki.cbor.CBORObject;
import org.webpki.cbor.CBORTextString;

import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONObjectWriter;
import org.webpki.json.JSONOutputFormats;


/**
 * The FWP PaymentRequest in JSON and CBOR format.
 */
public class FWPPaymentRequest {

    // Payment Request constants in CBOR
    public static final CBORInteger CBOR_PR_PAYEE_NAME  = new CBORInteger(1);
    public static final CBORInteger CBOR_PR_REQUEST_ID  = new CBORInteger(2);
    public static final CBORInteger CBOR_PR_AMOUNT      = new CBORInteger(3);
    public static final CBORInteger CBOR_PR_CURRENCY    = new CBORInteger(4);

    // Payment Request constants in JSON
    public static final String JSON_PR_PAYEE_NAME = "payeeName";
    public static final String JSON_PR_REQUEST_ID = "requestId";
    public static final String JSON_PR_AMOUNT     = "amount";
    public static final String JSON_PR_CURRENCY   = "currency";
    
    String payeeName;
    public String getPayeeName() {
        return payeeName;
    }

    String requestId;
    public String getRequestId() {
        return requestId;
    }

    String currency;
    public String getCurrency() {
        return currency;
    }
 
    String amount;
    public String getAmount() {
        return amount;
    }

    public FWPPaymentRequest(JSONObjectReader reader) throws IOException {
        payeeName = reader.getString(JSON_PR_PAYEE_NAME);
        requestId = reader.getString(JSON_PR_REQUEST_ID);
        amount = reader.getString(JSON_PR_AMOUNT);
        currency = reader.getString(JSON_PR_CURRENCY);
        reader.checkForUnread();
    }
    
    public FWPPaymentRequest(CBORObject cborObject) throws IOException {
        CBORMap cborPaymentRequest = cborObject.getMap();
        payeeName = cborPaymentRequest.getObject(CBOR_PR_PAYEE_NAME).getTextString();
        requestId = cborPaymentRequest.getObject(CBOR_PR_REQUEST_ID).getTextString();
        amount = cborPaymentRequest.getObject(CBOR_PR_AMOUNT).getTextString();
        currency = cborPaymentRequest.getObject(CBOR_PR_CURRENCY).getTextString();
        cborObject.checkForUnread();
    }
    
    public FWPPaymentRequest(String payeeName,
                             String requestId,
                             String amount,
                             String currency) {
        this.payeeName = payeeName;
        this.requestId = requestId;
        this.amount = amount;
        this.currency = currency;
    }
    
    public String serializeAsJSON() throws IOException {
        return serializeAsJSON(JSONOutputFormats.NORMALIZED);
    }
    
    public String serializeAsJSON(JSONOutputFormats format) throws IOException {
        return getWriter().serializeToString(format);
    }
    
    public CBORMap serializeAsCBOR() throws IOException {
        return new CBORMap()
                .setObject(CBOR_PR_PAYEE_NAME, new CBORTextString(payeeName))
                .setObject(CBOR_PR_REQUEST_ID, new CBORTextString(requestId))
                .setObject(CBOR_PR_AMOUNT, new CBORTextString(amount))
                .setObject(CBOR_PR_CURRENCY, new CBORTextString(currency));
    }

    public JSONObjectWriter getWriter() throws IOException {
        return new JSONObjectWriter()
                .setString(JSON_PR_PAYEE_NAME, payeeName)
                .setString(JSON_PR_REQUEST_ID, requestId)
                .setString(JSON_PR_AMOUNT, amount)
                .setString(JSON_PR_CURRENCY, currency);
    }
    
    @Override
    public String toString() {
        try {
            return getWriter().toString();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
    
    @Override
    public boolean equals(Object o) {
        try {
            return serializeAsCBOR().equals(((FWPPaymentRequest)o).serializeAsCBOR());
        } catch (IOException e) {
            return false;
        }
    }
}
