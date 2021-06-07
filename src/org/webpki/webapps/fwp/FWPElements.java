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
import org.webpki.cbor.CBORTextString;

import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONParser;

/**
 * All elements of an FWP assertion.
 * 
 */
public enum FWPElements {
    VERSION (1),
    PAYMENT_REQUEST(2),
    HOST_NAME(3);
    
    int cborLabel;

    FWPElements(int cborLabel) {
        this.cborLabel = cborLabel;
    }
    
    public static final String CURRENT_VERSION = "1.00";
    
    public static final int CBOR_PR_PAYEE       = 1;
    public static final int CBOR_PR_ID          = 2;
    public static final int CBOR_PR_AMOUNT      = 3;
    public static final int CBOR_PR_CURRENCY    = 4;

    public static final String JSON_PR_PAYEE    = "payee";
    public static final String JSON_PR_ID       = "id";
    public static final String JSON_PR_AMOUNT   = "amount";
    public static final String JSON_PR_CURRENCY = "currency";

    /**
     * Convert a payment request in JSON to CBOR.
     * 
     * @param paymentRequestJson
     * @return CBOR representation
     * @throws IOException
     */
    public static CBORMap convertPaymentRequest(String jsonString) throws IOException {
        JSONObjectReader jsonPaymentRequest = JSONParser.parse(jsonString);
        CBORMap cborPaymentRequest = new CBORMap()
            .setObject(CBOR_PR_PAYEE, 
                       new CBORTextString(jsonPaymentRequest.getString(JSON_PR_PAYEE)))
            .setObject(CBOR_PR_ID, 
                       new CBORTextString(jsonPaymentRequest.getString(JSON_PR_ID)))
            .setObject(CBOR_PR_AMOUNT, 
                       new CBORTextString(jsonPaymentRequest.getString(JSON_PR_AMOUNT)))
            .setObject(CBOR_PR_CURRENCY, 
                       new CBORTextString(jsonPaymentRequest.getString(JSON_PR_CURRENCY)));
        jsonPaymentRequest.checkForUnread();
        return cborPaymentRequest;
    }
}
    
