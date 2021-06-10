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
import org.webpki.cbor.CBORTextString;

import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONParser;

/**
 * All elements of an FWP assertion.
 * 
 */
public enum FWPElements {
    
    FWP_VERSION               (1),
    PAYMENT_REQUEST           (2),
    PAYEE_HOST_NAME           (3),
    ACCOUNT_ID                (4),
    SERIAL_NUMBER             (5),
    PAYMENT_METHOD            (6),
    NETWORK_DATA              (7),
    USER_AUTHORIZATION_METHOD (8),
    PLATFORM_DATA             (9),
    TIME_STAMP                (10),
    AUTHORIZATION             (11);
    
    
    int cborLabel;

    FWPElements(int cborLabel) {
        this.cborLabel = cborLabel;
    }
    
    public static final String CURRENT_VERSION = "1.00";
    
    // Payment Request
    public static final int CBOR_PR_PAYEE       = 1;
    public static final int CBOR_PR_ID          = 2;
    public static final int CBOR_PR_AMOUNT      = 3;
    public static final int CBOR_PR_CURRENCY    = 4;

    public static final String JSON_PR_PAYEE    = "payee";
    public static final String JSON_PR_ID       = "id";
    public static final String JSON_PR_AMOUNT   = "amount";
    public static final String JSON_PR_CURRENCY = "currency";
    
    // Platform Data
    public static final int CBOR_PD_OPERATING_SYSTEM = 1;
    public static final int CBOR_PD_USER_AGENT       = 2;
    // Platform Data sub elements
    public static final int CBOR_PDSUB_NAME          = 1;
    public static final int CBOR_PDSUB_VERSION       = 2;
    
    public static enum UserAuthorizationMethods {
    
        UNSPECIFIED     (0),
        FINGERPRINT     (1),
        FACERECOGNITION (2),
        PIN             (3);
        
        int cborValue;

        UserAuthorizationMethods(int cborValue) {
            this.cborValue = cborValue;
        }
    
    }

    static UserAuthorizationMethods getUserAuthorizationMethod(int cborValue) throws IOException {
        for (UserAuthorizationMethods userAuthMeth : UserAuthorizationMethods.values()) {
            if (userAuthMeth.cborValue == cborValue) {
                return userAuthMeth;
            }
        }
        throw new IOException("Unrecognized user authorization method: " + cborValue);
    }


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
        
        // Additional data is not permitted.
        jsonPaymentRequest.checkForUnread();
        return cborPaymentRequest;
    }
}
    
