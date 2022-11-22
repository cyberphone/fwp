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

import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONObjectWriter;
import org.webpki.json.JSONOutputFormats;

/**
 * The FWP Assertion as provided by the browser.
 */
public class FWPJsonAssertion {

    public static final String PAYMENT_NETWORK_ID      = "paymentNetworkId";
    public static final String ISSUER_ID               = "issuerId";
    public static final String ENCRYPTED_AUTHORIZATION = "encryptedAuthorization";
    
    String paymentNetworkId;
    public String getPaymentNetwordId() {
        return paymentNetworkId;
    }
    
    String issuerId;
    public String getIssuerId() {
        return issuerId;
    }
    
    byte[] encryptedAuthorization;
    public byte[] getEncryptedAuthorization() {
        return encryptedAuthorization;
    }
    
    public FWPJsonAssertion(JSONObjectReader reader) throws IOException {
        paymentNetworkId = reader.getString(PAYMENT_NETWORK_ID);
        issuerId = reader.getString(ISSUER_ID);
        encryptedAuthorization = reader.getBinary(ENCRYPTED_AUTHORIZATION);
    }
    
    public FWPJsonAssertion(String paymentNetworkId,
                            String issuerId,
                            byte[] encryptedAuthorization) {
        this.paymentNetworkId = paymentNetworkId;
        this.issuerId = issuerId;
        this.encryptedAuthorization = encryptedAuthorization;
    }
    
    public String serialize() throws IOException {
        return getWriter().serializeToString(JSONOutputFormats.NORMALIZED);
    }
    
    public JSONObjectWriter getWriter() throws IOException {
        return new JSONObjectWriter()
                .setString(PAYMENT_NETWORK_ID, paymentNetworkId)
                .setString(ISSUER_ID, issuerId)
                .setBinary(ENCRYPTED_AUTHORIZATION, encryptedAuthorization);
    }
    
    @Override
    public String toString() {
        try {
            return getWriter().toString();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
