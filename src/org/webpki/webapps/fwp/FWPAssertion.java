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

import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.crypto.HashAlgorithms;
import org.webpki.crypto.SignatureWrapper;

import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONParser;

import org.webpki.util.ArrayUtil;

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
    
    private static final int COSE_ALGORITHM_HOLDER = 3;
    
    static int publicKey2CoseSignatureAlgorithm(PublicKey publicKey) {
        if (publicKey instanceof RSAKey) {
            return -257;
        }
        if (publicKey instanceof ECKey) {
            return -7;
        }
        return -8;
    }
    
    static AsymSignatureAlgorithms getWebPkiAlgorithm(int coseAlgorithm) {
        switch (coseAlgorithm) {
            case -7: 
                return AsymSignatureAlgorithms.ECDSA_SHA256;

            case -257: 
                return AsymSignatureAlgorithms.RSA_SHA256;

            default:
                return AsymSignatureAlgorithms.ED25519;
        }
    }
    
    private static void algorithmComplianceTest(PublicKey publicKey, int algorithm)
            throws GeneralSecurityException {
        if (publicKey2CoseSignatureAlgorithm(publicKey) != algorithm) {
            throw new GeneralSecurityException("Algorithm ("  + algorithm + 
                    ") does not match public key type: " + publicKey.getAlgorithm());
        }
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
                .setObject(AC_ALGORITHM, new CBORInteger(publicKey2CoseSignatureAlgorithm(publicKey)))
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
        return fwpAssertion.encode();
    }

    static void validateFidoSignature(AsymSignatureAlgorithms algorithm, 
                                      PublicKey publicKey,
                                      byte[] authenticatorData,
                                      byte[] clientDataJSON,
                                      byte[] signature) throws IOException,
                                                               GeneralSecurityException  {
        if (!new SignatureWrapper(algorithm, publicKey)
                .setEcdsaSignatureEncoding(true)
                .update(ArrayUtil.add(authenticatorData,
                                      HashAlgorithms.SHA256.digest(clientDataJSON)))
                .verify(signature)) {
            throw new GeneralSecurityException("Signature validation failed");
        }       
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
        int signatureAlgorithm = authorization.getObject(AC_ALGORITHM).getInt();
        authorization.checkObjectForUnread();
        algorithmComplianceTest(publicKey, signatureAlgorithm);
        
        // We are nice and do not touch the original assertion.
        CBORIntegerMap copyOfAssertion = CBORObject.decode(fwpAssertion.encode()).getIntegerMap();
        CBORIntegerMap copyOfAuthorization = 
                copyOfAssertion.getObject(OUTER_AUTHORIZATION).getIntegerMap();

        // The following element do not participate in the signature generation
        // and must therefore be removed from the assertion (after first having
        // been fetched).
        copyOfAuthorization.removeObject(AC_AUTHENTICATOR_DATA);
        copyOfAuthorization.removeObject(AC_CLIENT_DATA_JSON);
        copyOfAuthorization.removeObject(AC_SIGNATURE);
        
        // This is not WebAuthn, it is FIDO Web Pay.
        if (!ArrayUtil.compare(HashAlgorithms.SHA256.digest(copyOfAssertion.encode()),
                               JSONParser.parse(clientDataJSON).getBinary(FWPCommon.CHALLENGE))) {
            throw new GeneralSecurityException("Message hash mismatch");
        }
        
        // Everything is good so far, now take on the signature.
        validateFidoSignature(getWebPkiAlgorithm(signatureAlgorithm),
                              publicKey,
                              authenticatorData,
                              clientDataJSON,
                              signature);

        // Return a hash of the public key for looking up in the RP database.
        return HashAlgorithms.SHA256.digest(cborPublicKey.encode());
    }

    static byte[] extractFidoPublicKey(byte[] attestationObject) throws IOException,
                                                                        GeneralSecurityException {
        // Digging out the COSE public key is somewhat difficult...
        byte[] authData = CBORObject.decode(attestationObject)
                .getTextStringMap().getObject("authData").getByteString();
        if ((authData[32] & (FWPCommon.FLAG_AT + FWPCommon.FLAG_ED)) != FWPCommon.FLAG_AT) {
            throw new GeneralSecurityException("Unsupported authData flags: " + authData[32]);
        }
        int i = 32 + 1 + 4 + 16;
        int credentialIdLength = (authData[i++] << 8) + authData[i++];
        int offset = i + credentialIdLength;
        byte[] rawPublicKey = new byte[authData.length - offset];
        System.arraycopy(authData, offset, rawPublicKey, 0, rawPublicKey.length);

        // Verify that we actually got a genuine FIDO public key.
        // Verify the algorithm but remove it from the public key object.
        CBORIntegerMap fidoPublicKey = CBORObject.decode(rawPublicKey).getIntegerMap();
        int algorithm = fidoPublicKey.getObject(COSE_ALGORITHM_HOLDER).getInt();
        fidoPublicKey.removeObject(COSE_ALGORITHM_HOLDER);
        PublicKey publicKey = CBORPublicKey.decode(fidoPublicKey);
        algorithmComplianceTest(publicKey, algorithm);
        return fidoPublicKey.encode();
    }
}
