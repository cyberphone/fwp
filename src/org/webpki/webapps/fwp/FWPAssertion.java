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

import java.security.GeneralSecurityException;
import java.security.PublicKey;

import java.security.interfaces.ECKey;
import java.security.interfaces.RSAKey;

import org.webpki.cbor.CBORByteString;
import org.webpki.cbor.CBORInteger;
import org.webpki.cbor.CBORIntegerMap;
import org.webpki.cbor.CBORObject;
import org.webpki.cbor.CBORPublicKey;
import org.webpki.cbor.CBORTextString;

import org.webpki.crypto.HashAlgorithms;
import org.webpki.crypto.KeyAlgorithms;
import org.webpki.crypto.SignatureWrapper;

import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONParser;

import org.webpki.util.ArrayUtil;
import org.webpki.util.DebugFormatter;

/**
 * Core FWP assertion support.
 */
public class FWPAssertion {
    
    // JSON payment request properties and their CBOR correspondents
    static final String JSON_PR_PAYEE     = "payee";
    static final int PR_PAYEE             = -1;
    
    static final String JSON_PR_ID        = "id";
    static final int PR_ID                = -2;

    static final String JSON_PR_AMOUNT    = "amount";
    static final int PR_AMOUNT            = -3;
    
    static final String JSON_PR_CURRENCY  = "currency";
    static final int PR_CURRENCY          = -4;
    
    static final String JSON_HOST_NAME       = "hostName";
    static final String JSON_PAYMENT_REQUEST = "paymentRequest";

    // Outermost CBOR keys
    private static final int OUTER_PAYMENT_REQUEST = 1;
    private static final int OUTER_HOST_NAME       = 2;
    private static final int OUTER_AUTHORIZATION   = 3;
    
    // Authorization signature container
    private static final int AC_ALGORITHM          = -1;
    private static final int AC_PUBLIC_KEY         = -2;
    private static final int AC_AUTHENTICATOR_DATA = -3;
    private static final int AC_CLIENT_DATA_JSON   = -4;
    private static final int AC_SIGNATURE          = -5;
    
    static int fidoPubKey2CoseSigAlg(PublicKey publicKey) {
        if (publicKey instanceof RSAKey) {
            return -257;
        }
        if (publicKey instanceof ECKey) {
            return -7;
        }
        return -8;
    }
    
    static CBORIntegerMap convertPaymentRequest(JSONObjectReader paymentRequestJson)
            throws IOException {
        CBORIntegerMap paymentRequest = new CBORIntegerMap()
            .setObject(PR_PAYEE, 
                       new CBORTextString(paymentRequestJson.getString(JSON_PR_PAYEE)))
            .setObject(PR_ID, 
                       new CBORTextString(paymentRequestJson.getString(JSON_PR_ID)))
            .setObject(PR_AMOUNT, 
                       new CBORTextString(paymentRequestJson.getString(JSON_PR_AMOUNT)))
            .setObject(PR_CURRENCY, 
                       new CBORTextString(paymentRequestJson.getString(JSON_PR_CURRENCY)));
        paymentRequestJson.checkForUnread();
        return paymentRequest;
    }

    static byte[] createDataToBeSigned(JSONObjectReader fwpInput, PublicKey publicKey) 
            throws IOException, GeneralSecurityException {
        CBORIntegerMap unsignedAssertion = new CBORIntegerMap()
            .setObject(OUTER_PAYMENT_REQUEST, 
                       convertPaymentRequest(fwpInput.getObject(JSON_PAYMENT_REQUEST)))
            .setObject(OUTER_HOST_NAME, new CBORTextString(fwpInput.getString(JSON_HOST_NAME)))
            .setObject(OUTER_AUTHORIZATION, new CBORIntegerMap()
                .setObject(AC_ALGORITHM, new CBORInteger(fidoPubKey2CoseSigAlg(publicKey)))
                .setObject(AC_PUBLIC_KEY, CBORPublicKey.encode(publicKey)));
        return unsignedAssertion.encode();
    }

    static byte[] finalizeAssertion(byte[] unsignedAssertion,
                                    byte[] authenticatorData,
                                    byte[] clientDataJSON,
                                    byte[] signature) throws IOException {
        CBORIntegerMap fwpAssertion = CBORObject.decode(unsignedAssertion).getIntegerMap();
        fwpAssertion.getObject(OUTER_AUTHORIZATION).getIntegerMap()
            .setObject(AC_AUTHENTICATOR_DATA, new CBORByteString(authenticatorData))
            .setObject(AC_CLIENT_DATA_JSON, new CBORByteString(clientDataJSON))
            .setObject(AC_SIGNATURE, new CBORByteString(signature));
        System.out.println(fwpAssertion.toString());
        return fwpAssertion.encode();
    }
    
    static byte[] validateFwpAssertion(CBORIntegerMap fwpAssertion)
            throws IOException, GeneralSecurityException {
        CBORIntegerMap authorization = 
                fwpAssertion.getObject(OUTER_AUTHORIZATION).getIntegerMap();
        byte[] signature = authorization.getObject(AC_SIGNATURE).getByteString();
        byte[] clientDataJSON = authorization.getObject(AC_CLIENT_DATA_JSON).getByteString();
        byte[] authenticatorData = authorization.getObject(AC_AUTHENTICATOR_DATA).getByteString();
        CBORObject cborPublicKey = authorization.getObject(AC_PUBLIC_KEY);
        PublicKey publicKey = CBORPublicKey.decode(cborPublicKey);
        if (fidoPubKey2CoseSigAlg(publicKey) != authorization.getObject(AC_ALGORITHM).getInt()) {
            throw new GeneralSecurityException("Algorithm does not match public key");
        }
        // We are nice and do not touch the original assertion.
        CBORIntegerMap copy = CBORObject.decode(fwpAssertion.encode()).getIntegerMap();
        CBORIntegerMap copyOfAuthorization = copy.getObject(OUTER_AUTHORIZATION).getIntegerMap();

        // The following element do not participate in the signature generation
        // and must therefore be removed from the CBOR object but must be fetched
        // in advance for signature validation.
        copyOfAuthorization.removeObject(AC_AUTHENTICATOR_DATA);
        copyOfAuthorization.removeObject(AC_CLIENT_DATA_JSON);
        copyOfAuthorization.removeObject(AC_SIGNATURE);
        
        // This is not WebAuthn, it is FIDO2.
        if (!ArrayUtil.compare(HashAlgorithms.SHA256.digest(copy.encode()),
                               JSONParser.parse(clientDataJSON).getBinary(FWPCommon.CHALLENGE))) {
            throw new GeneralSecurityException("Message hash mismatch");
        }
        KeyAlgorithms keyAlgorithm = 
                KeyAlgorithms.getKeyAlgorithm(publicKey);
        if (!new SignatureWrapper(keyAlgorithm.getRecommendedSignatureAlgorithm(), publicKey)
                .setEcdsaSignatureEncoding(true)
                .update(ArrayUtil.add(authenticatorData,
                                      HashAlgorithms.SHA256.digest(clientDataJSON)))
                .verify(signature)) {
            throw new GeneralSecurityException("Signature validation failed");
        }
        authorization.checkObjectForUnread();
        System.out.println(cborPublicKey.toString());
        return HashAlgorithms.SHA256.digest(cborPublicKey.encode());
    }
}
