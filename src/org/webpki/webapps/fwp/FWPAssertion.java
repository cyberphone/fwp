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
    
    private FWPAssertion() {}
    
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
    
    // Authorization Signature (AS) container
    private static final int AS_ALGORITHM          = -1;
    private static final int AS_PUBLIC_KEY         = -2;
    private static final int AS_AUTHENTICATOR_DATA = -3;
    private static final int AS_CLIENT_DATA_JSON   = -4;
    private static final int AS_SIGNATURE          = -5;
    
    private static final int COSE_ALGORITHM_HOLDER = 3;

    /**
     * Public key to to COSE signature algorithm.
     * 
     * FIDO does currently not permit multiple signature algorithms per key algorithm.
     * 
     * @param publicKey Public key in Java notation
     * @return COSE signature algorithm
     */
    public static int publicKey2CoseSignatureAlgorithm(PublicKey publicKey) {
        if (publicKey instanceof RSAKey) {
            return -257;
        }
        if (publicKey instanceof ECKey) {
            return -7;
        }
        return -8;
    }

    /**
     * COSE algorithm to WebPKI algorithm.
     * 
     * @param coseAlgorithm COSE signature algorithm
     * @return WebPKI signature algorithm
     */
    public static AsymSignatureAlgorithms getWebPkiAlgorithm(int coseAlgorithm) {
        if (coseAlgorithm == -257) {
            return AsymSignatureAlgorithms.RSA_SHA256;
        } else if (coseAlgorithm == -7) {
            return AsymSignatureAlgorithms.ECDSA_SHA256;
        }
        return AsymSignatureAlgorithms.ED25519;
    }
    
    static void algorithmComplianceTest(PublicKey publicKey, int algorithm)
            throws GeneralSecurityException {
        if (publicKey2CoseSignatureAlgorithm(publicKey) != algorithm) {
            throw new GeneralSecurityException("Algorithm ("  + algorithm + 
                    ") does not match public key type: " + publicKey.getAlgorithm());
        }
    }
    
    /**
     * Convert a payment request in JSON to CBOR.
     * 
     * @param paymentRequestJson
     * @return CBOR representation
     * @throws IOException
     */
    public static CBORIntegerMap convertPaymentRequest(JSONObjectReader paymentRequestJson)
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

    public static byte[] createDataToBeSigned(JSONObjectReader fwpInput, 
                                              PublicKey publicKey) 
            throws IOException, GeneralSecurityException {
        CBORIntegerMap unsignedAssertion = new CBORIntegerMap()
            .setObject(OUTER_PAYMENT_REQUEST, 
                       convertPaymentRequest(fwpInput.getObject(JSON_PAYMENT_REQUEST)))
            .setObject(OUTER_HOST_NAME, new CBORTextString(fwpInput.getString(JSON_HOST_NAME)))
            .setObject(OUTER_AUTHORIZATION, new CBORIntegerMap()
                .setObject(AS_ALGORITHM, 
                           new CBORInteger(publicKey2CoseSignatureAlgorithm(publicKey)))
                .setObject(AS_PUBLIC_KEY, CBORPublicKey.encode(publicKey)));
        return unsignedAssertion.encode();
    }

    public static byte[] finalizeAssertion(CBORIntegerMap unsignedAssertion,
                                           byte[] authenticatorData,
                                           byte[] clientDataJSON,
                                           byte[] signature) throws IOException {
        unsignedAssertion.getObject(OUTER_AUTHORIZATION).getIntegerMap()
            .setObject(AS_AUTHENTICATOR_DATA, new CBORByteString(authenticatorData))
            .setObject(AS_CLIENT_DATA_JSON, new CBORByteString(clientDataJSON))
            .setObject(AS_SIGNATURE, new CBORByteString(signature));
        return unsignedAssertion.encode();
    }

    /**
     * Validate FIDO signature.
     * 
     * @param algorithm Signature algorithm in WebPKI notation
     * @param publicKey Public key in Java format
     * @param authenticatorData FIDO core data
     * @param clientDataJSON FIDO core data
     * @param signature FIDO core data
     * @throws IOException
     * @throws GeneralSecurityException
     */
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

    /**
     * Validate FWP assertion with respect to crypto.
     * 
     * @param fwpAssertion FWP assertion
     * @return Public key in COSE format
     * @throws IOException
     * @throws GeneralSecurityException
     */
    public static byte[] validateFwpAssertion(CBORIntegerMap fwpAssertion)
            throws IOException, GeneralSecurityException {
        CBORIntegerMap authorization = 
                fwpAssertion.getObject(OUTER_AUTHORIZATION).getIntegerMap();
        byte[] signature = authorization.getObject(AS_SIGNATURE).getByteString();
        byte[] clientDataJSON = authorization.getObject(AS_CLIENT_DATA_JSON).getByteString();
        byte[] authenticatorData = authorization.getObject(AS_AUTHENTICATOR_DATA).getByteString();
        CBORObject cborPublicKey = authorization.getObject(AS_PUBLIC_KEY);
        PublicKey publicKey = CBORPublicKey.decode(cborPublicKey);
        int signatureAlgorithm = authorization.getObject(AS_ALGORITHM).getInt();
        authorization.checkObjectForUnread();
        algorithmComplianceTest(publicKey, signatureAlgorithm);
        
        // We are nice and do not touch the original assertion.
        CBORIntegerMap copyOfAssertion = CBORObject.decode(fwpAssertion.encode()).getIntegerMap();
        CBORIntegerMap copyOfAuthorization = 
                copyOfAssertion.getObject(OUTER_AUTHORIZATION).getIntegerMap();

        // The following element do not participate in the signature generation
        // and must therefore be removed from the assertion (after first having
        // been fetched).
        copyOfAuthorization.removeObject(AS_AUTHENTICATOR_DATA);
        copyOfAuthorization.removeObject(AS_CLIENT_DATA_JSON);
        copyOfAuthorization.removeObject(AS_SIGNATURE);
        
        // This is not WebAuthn, this is FIDO Web Pay.
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

        // Return the public key for looking up in an RP database.
        return cborPublicKey.encode();
    }

    /**
     * Extract the public key from a FIDO attestation.
     * 
     * @param attestationObject Created by the registration call
     * @return Public key in COSE format
     * @throws IOException
     * @throws GeneralSecurityException
     */
    public static byte[] extractFidoPublicKey(byte[] attestationObject) 
            throws IOException, GeneralSecurityException {
        // Digging out the COSE public key is somewhat awkward...
        byte[] authData = CBORObject.decode(attestationObject)
                .getTextStringMap().getObject("authData").getByteString();
        if ((authData[32] & (FWPCommon.FLAG_AT + FWPCommon.FLAG_ED)) != FWPCommon.FLAG_AT) {
            throw new GeneralSecurityException("Unsupported authData flags: 0x" + 
                                               String.format("%2x", authData[32] & 0xff));
        }
        int i = 32 + 1 + 4 + 16;
        int credentialIdLength = (authData[i++] << 8) + authData[i++];
        int offset = i + credentialIdLength;
        byte[] rawPublicKey = new byte[authData.length - offset];
        System.arraycopy(authData, offset, rawPublicKey, 0, rawPublicKey.length);

        // Verify that we actually got a genuine FIDO public key.
        // Then verify the algorithm but remove it from the public key object.
        CBORIntegerMap fidoPublicKey = CBORObject.decode(rawPublicKey).getIntegerMap();
        int algorithm = fidoPublicKey.getObject(COSE_ALGORITHM_HOLDER).getInt();
        fidoPublicKey.removeObject(COSE_ALGORITHM_HOLDER);
        PublicKey publicKey = CBORPublicKey.decode(fidoPublicKey);
        algorithmComplianceTest(publicKey, algorithm);
        return fidoPublicKey.encode();
    }
}
