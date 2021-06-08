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
import java.security.PublicKey;

import java.security.interfaces.ECKey;
import java.security.interfaces.RSAKey;

import org.webpki.cbor.CBORByteString;
import org.webpki.cbor.CBORInteger;
import org.webpki.cbor.CBORMap;
import org.webpki.cbor.CBORObject;
import org.webpki.cbor.CBORPublicKey;
import org.webpki.cbor.CBORTextString;

import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.crypto.HashAlgorithms;

import org.webpki.crypto.signatures.SignatureWrapper;

import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONParser;

import org.webpki.util.ArrayUtil;

/**
 * FWP and FIDO crypto support.
 */
public class FWPCrypto {
    
    private FWPCrypto() {}
    
    // FIDO call data
    public static final String USER_ID                  = "userId";
    public static final String CHALLENGE                = "challenge";

    // Returned FIDO data
    public static final String CREDENTIAL_ID            = "credentialId";
    public static final String ATTESTATION_OBJECT       = "attestationObject";
    public static final String CLIENT_DATA_JSON         = "clientDataJSON";
    public static final String AUTHENTICATOR_DATA_JSON  = "authenticatorData";
    public static final String SIGNATURE_JSON           = "signature";

    // Attestation Object flags
    static final int    FLAG_ED                  = 0x80;
    static final int    FLAG_AT                  = 0x40;
    
   
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
    
    private static final int COSE_ALGORITHM_LABEL  = 3;

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
    public static AsymSignatureAlgorithms getWebPkiAlgorithm(int coseAlgorithm) 
            throws GeneralSecurityException {
        switch (coseAlgorithm) {
            case -257:
                return AsymSignatureAlgorithms.RSA_SHA256;
    
            case  -7:
                return AsymSignatureAlgorithms.ECDSA_SHA256;
            
            case -8:
                return AsymSignatureAlgorithms.ED25519;
    
            default:
                throw new GeneralSecurityException("Unexpected signature algorithm: " + coseAlgorithm);
        }
    }
    
    static void algorithmComplianceTest(PublicKey publicKey, int coseAlgorithm)
            throws GeneralSecurityException {
        if (publicKey2CoseSignatureAlgorithm(publicKey) != coseAlgorithm) {
            throw new GeneralSecurityException("Algorithm ("  + coseAlgorithm + 
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
    public static CBORMap convertPaymentRequest(JSONObjectReader paymentRequestJson)
            throws IOException {
        CBORMap paymentRequest = new CBORMap()
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
        CBORMap unsignedAssertion = new CBORMap()
            .setObject(OUTER_PAYMENT_REQUEST, 
                       convertPaymentRequest(fwpInput.getObject(JSON_PAYMENT_REQUEST)))
            .setObject(OUTER_HOST_NAME, new CBORTextString(fwpInput.getString(JSON_HOST_NAME)))
            .setObject(OUTER_AUTHORIZATION, new CBORMap()
                .setObject(AS_ALGORITHM, 
                           new CBORInteger(publicKey2CoseSignatureAlgorithm(publicKey)))
                .setObject(AS_PUBLIC_KEY, CBORPublicKey.encode(publicKey)));
        return unsignedAssertion.encode();
    }

    public static byte[] finalizeAssertion(CBORMap unsignedAssertion,
                                           byte[] authenticatorData,
                                           byte[] clientDataJSON,
                                           byte[] signature) throws IOException {
        unsignedAssertion.getObject(OUTER_AUTHORIZATION).getMap()
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
    public static void validateFidoSignature(AsymSignatureAlgorithms algorithm, 
                                             PublicKey publicKey,
                                             byte[] authenticatorData,
                                             byte[] clientDataJSON,
                                             byte[] signature) throws IOException,
                                                                      GeneralSecurityException {
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
    public static byte[] validateFwpAssertion(CBORMap fwpAssertion)
            throws IOException, GeneralSecurityException {
        CBORMap authorization = fwpAssertion.getObject(OUTER_AUTHORIZATION).getMap();
        byte[] signature = authorization.getObject(AS_SIGNATURE).getByteString();
        byte[] clientDataJSON = authorization.getObject(AS_CLIENT_DATA_JSON).getByteString();
        byte[] authenticatorData = authorization.getObject(AS_AUTHENTICATOR_DATA).getByteString();
        CBORObject cborPublicKey = authorization.getObject(AS_PUBLIC_KEY);
        PublicKey publicKey = CBORPublicKey.decode(cborPublicKey);
        int coseAlgorithm = authorization.getObject(AS_ALGORITHM).getInt();
        authorization.checkObjectForUnread();
        algorithmComplianceTest(publicKey, coseAlgorithm);
        
        // We are nice and do not touch the original assertion.
        CBORMap copyOfAssertion = CBORObject.decode(fwpAssertion.encode()).getMap();
        CBORMap copyOfAuthorization = copyOfAssertion.getObject(OUTER_AUTHORIZATION).getMap();

        // The following element do not participate in the signature generation
        // and must therefore be removed from the assertion (after first having
        // been fetched).
        copyOfAuthorization.removeObject(AS_AUTHENTICATOR_DATA);
        copyOfAuthorization.removeObject(AS_CLIENT_DATA_JSON);
        copyOfAuthorization.removeObject(AS_SIGNATURE);
        
        // This is not WebAuthn, this is FIDO Web Pay.  "challenge" = hash of FWP data.
        if (!ArrayUtil.compare(HashAlgorithms.SHA256.digest(copyOfAssertion.encode()),
                               JSONParser.parse(clientDataJSON).getBinary(CHALLENGE))) {
            throw new GeneralSecurityException("Message hash mismatch");
        }
        
        // Everything is good so far, now take on the signature.
        validateFidoSignature(getWebPkiAlgorithm(coseAlgorithm),
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
                .getMap().getObject("authData").getByteString();
        if ((authData[32] & FLAG_AT) == 0) {
            throw new GeneralSecurityException("Unsupported authData flags: 0x" + 
                                               String.format("%2x", authData[32] & 0xff));
        }
        int i = 32 + 1 + 4 + 16;
        int credentialIdLength = (authData[i++] << 8) + authData[i++];
        int offset = i + credentialIdLength;
        byte[] rawPublicKeyAndOptionalExtensionData = new byte[authData.length - offset];
        System.arraycopy(authData,
                         offset, 
                         rawPublicKeyAndOptionalExtensionData, 
                         0,
                         rawPublicKeyAndOptionalExtensionData.length);

        // We silently drop possible Extension Data (ED).
        CBORMap fidoPublicKey = CBORObject.decodeWithOptions(rawPublicKeyAndOptionalExtensionData,
                                                             true, 
                                                             false).getMap();

        // Fetch the signature algorithm but remove it from the public key object.
        int signatureAlgorithm = fidoPublicKey.getObject(COSE_ALGORITHM_LABEL).getInt();
        fidoPublicKey.removeObject(COSE_ALGORITHM_LABEL);

        // Verify that we got a genuine FIDO/COSE public key and
        // that the associated signature algorithm matches.
        PublicKey publicKey = CBORPublicKey.decode(fidoPublicKey);
        algorithmComplianceTest(publicKey, signatureAlgorithm);
        
        // Back to black (raw) :)
        return fidoPublicKey.encode();
    }
}
