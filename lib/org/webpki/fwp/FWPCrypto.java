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

import java.net.URL;

import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;

import java.security.interfaces.ECKey;
import java.security.interfaces.RSAKey;

import org.webpki.cbor.CBORByteString;
import org.webpki.cbor.CBORInteger;
import org.webpki.cbor.CBORMap;
import org.webpki.cbor.CBORObject;
import org.webpki.cbor.CBORPublicKey;

import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.crypto.HashAlgorithms;

import org.webpki.crypto.signatures.SignatureWrapper;

import org.webpki.json.JSONObjectWriter;
import org.webpki.json.JSONOutputFormats;
import org.webpki.json.JSONParser;

import org.webpki.util.ArrayUtil;

/**
 * FWP and FIDO crypto support.
 */
public class FWPCrypto {
    
    private static byte[] addRemainingElements(CBORMap cborFwpAssertion,
                                               byte[] clientDataJSON,
                                               byte[] authenticatorData,
                                               byte[] signature) throws IOException {
        cborFwpAssertion.getObject(FWPElements.AUTHORIZATION.cborLabel).getMap()
            .setObject(AS_CLIENT_DATA_JSON, 
                       new CBORByteString(clientDataJSON))
            .setObject(AS_AUTHENTICATOR_DATA,
                       new CBORByteString(authenticatorData))
            .setObject(AS_SIGNATURE,
                       new CBORByteString(signature));
        return cborFwpAssertion.encode();
    }

    public static byte[] AddPostSignature(byte[] fwpAssertionPlus,
                                          byte[] clientDataJSON,
                                          byte[] authenticatorData,
                                          byte[] signature) throws IOException,
                                                                   GeneralSecurityException {
        if (!ArrayUtil.compare(HashAlgorithms.SHA256.digest(fwpAssertionPlus),
                               JSONParser.parse(clientDataJSON).getBinary(CHALLENGE))) {
            throw new GeneralSecurityException("Message hash mismatch");
        }
        CBORMap cborFwpAssertion = CBORObject.decode(fwpAssertionPlus).getMap();
        return addRemainingElements(cborFwpAssertion, clientDataJSON, authenticatorData, signature);
    }
    
    public static byte[] directSign(byte[] fwpAssertionPlus,
                                    PrivateKey privateKey,
                                    String origin) throws IOException,
                                                                    GeneralSecurityException {
        CBORMap cborFwpAssertion = CBORObject.decode(fwpAssertionPlus).getMap();
        int coseAlgorithm = cborFwpAssertion.getObject(FWPElements.AUTHORIZATION.cborLabel)
                .getMap().getObject(AS_ALGORITHM).getInt();
        byte[] challenge = HashAlgorithms.SHA256.digest(fwpAssertionPlus);
        // Now we have the data needed for creating the FIDI ClientDataJSON object.
        byte[] clientDataJSON = new JSONObjectWriter()
                .setString(CDJ_TYPE, CDJ_GET_ARGUMENT)
                .setString(CDJ_ORIGIN, origin)
                .setBinary(CHALLENGE, challenge)
                .serializeToBytes(JSONOutputFormats.NORMALIZED);
        
        // Hard-coded FIDO Authenticator Data
        byte[] authenticatorData = ArrayUtil.add(
                HashAlgorithms.SHA256.digest(new URL(origin).getHost().getBytes("utf-8")),
                                             new byte[] {1, 0, 0 ,0, 0});
        
        // Create FIDO signature.
        byte[] signature = new SignatureWrapper(getWebPkiAlgorithm(coseAlgorithm), privateKey)
                .setEcdsaSignatureEncoding(true)
                .update(authenticatorData)
                .update(HashAlgorithms.SHA256.digest(clientDataJSON))
                .sign();
        return addRemainingElements(cborFwpAssertion, clientDataJSON, authenticatorData, signature);
    }

    public static class FWPPreSigner  {

        PublicKey publicKey;
        
        public FWPPreSigner(PublicKey publicKey) {
            this.publicKey = publicKey;
        }

        CBORMap appendSignatureObject(CBORMap fwpAssertion) 
                throws IOException, GeneralSecurityException {
            int coseAlgorithm = publicKey2CoseSignatureAlgorithm(publicKey);
            
            // Add the authorization container map including the members that
            // also are signed.
            return new CBORMap()
                .setObject(AS_ALGORITHM, new CBORInteger(coseAlgorithm))
                .setObject(AS_PUBLIC_KEY,
                           CBORPublicKey.encode(publicKey));
        }
    }
    
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
    public static final int    FLAG_ED                  = 0x80;
    public static final int    FLAG_AT                  = 0x40;
    
    // ClientDataJSON
    public static final String CDJ_TYPE                 = "type";
    public static final String CDJ_ORIGIN               = "origin";
    public static final String CDJ_CREATE_ARGUMENT      = "webauthn.create";
    public static final String CDJ_GET_ARGUMENT         = "webauthn.get";
    
    // Authorization Signature (AS) container
    static final int AS_ALGORITHM          = 1;
    static final int AS_PUBLIC_KEY         = 2;
    static final int AS_AUTHENTICATOR_DATA = 3;
    static final int AS_CLIENT_DATA_JSON   = 4;
    static final int AS_SIGNATURE          = 5;
    
    static final int COSE_ALGORITHM_LABEL  = 3;

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
                throw new GeneralSecurityException("Unexpected signature algorithm: " + 
                                                   coseAlgorithm);
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
    public static byte[] validateFwpAssertion(CBORMap fwpAssertion,
                                              int authorizationLabel)
            throws IOException, GeneralSecurityException {
        CBORMap authorization = fwpAssertion.getObject(authorizationLabel).getMap();
        byte[] signature = authorization.getObject(AS_SIGNATURE).getByteString();
        byte[] clientDataJSON = authorization.getObject(AS_CLIENT_DATA_JSON).getByteString();
        byte[] authenticatorData = authorization.getObject(AS_AUTHENTICATOR_DATA).getByteString();
        CBORObject cborPublicKey = authorization.getObject(AS_PUBLIC_KEY);
        PublicKey publicKey = CBORPublicKey.decode(cborPublicKey);
        int coseAlgorithm = authorization.getObject(AS_ALGORITHM).getInt();
        algorithmComplianceTest(publicKey, coseAlgorithm);
        
        // We are nice and do not touch the original assertion.
        CBORMap copyOfAssertion = CBORObject.decode(fwpAssertion.encode()).getMap();
        CBORMap copyOfAuthorization = copyOfAssertion.getObject(authorizationLabel).getMap();

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
