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

import java.io.ByteArrayInputStream;
import java.io.IOException;

import java.net.URL;

import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;

import java.security.interfaces.ECKey;
import java.security.interfaces.RSAKey;

import java.util.Arrays;
import java.util.HashSet;

import org.webpki.cbor.CBORBytes;
import org.webpki.cbor.CBORDecoder;
import org.webpki.cbor.CBORInt;
import org.webpki.cbor.CBORMap;
import org.webpki.cbor.CBORObject;
import org.webpki.cbor.CBORPublicKey;
import org.webpki.cbor.CBORString;

import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.crypto.CryptoException;
import org.webpki.crypto.HashAlgorithms;
import org.webpki.crypto.SignatureWrapper;

import org.webpki.json.JSONObjectWriter;
import org.webpki.json.JSONOutputFormats;
import org.webpki.json.JSONParser;

import org.webpki.util.UTF8;

/**
 * FWP and FIDO crypto support.
 */
public class FWPCrypto {
    
    private FWPCrypto() {}
    
    // ESAD container Id
    public static final String FWP_ESAD_OBJECT_ID   = "https://fido-web-pay.github.io/ns/p1";
    
    // FIDO call data
    public static final String CREDENTIAL_ID        = "credentialId";
    public static final String USER_ID              = "userId";
    public static final String CHALLENGE            = "challenge";

    // Returned FIDO data
    public static final String ATTESTATION_OBJECT   = "attestationObject";
    public static final String CLIENT_DATA_JSON     = "clientDataJSON";
    public static final String AUTHENTICATOR_DATA   = "authenticatorData";
    public static final String SIGNATURE            = "signature";
    
    // For FIDO attestations only
    public static final CBORString AUTH_DATA_CBOR = new CBORString("authData");

    // Attestation Object flags
    public static final int    FLAG_UP              = 0x01;
    public static final int    FLAG_UV              = 0x04;
    public static final int    FLAG_AT              = 0x40;
    public static final int    FLAG_ED              = 0x80;
    
    // ClientDataJSON
    public static final String CDJ_TYPE             = "type";
    public static final String CDJ_ORIGIN           = "origin";
    public static final String CDJ_CREATE_ARGUMENT  = "webauthn.create";
    public static final String CDJ_GET_ARGUMENT     = "webauthn.get";
    
    // FIDO/COSE key algorithm Ids
    public static final int FIDO_KEYALG_ES256       = -7;
    public static final int FIDO_KEYALG_ED25519     = -8;    // Not really COSE...
    public static final int FIDO_KEYALG_RS256       = -257;
    
    // Authorization Signature (AS) container
    public static final CBORInt AS_ALGORITHM            = new CBORInt(1);
    public static final CBORInt AS_PUBLIC_KEY           = new CBORInt(2);
    public static final CBORInt AS_AUTHENTICATOR_DATA   = new CBORInt(3);
    public static final CBORInt AS_SIGNATURE            = new CBORInt(4);
    
    // Used by the Web emulator to maintain WebAuthn compatibility
    public static final CBORInt AS_CLIENT_DATA_JSON     = new CBORInt(5);
    
    // For attestation public key objects
    static final CBORInt COSE_ALGORITHM_LABEL           = new CBORInt(3);
    
    // authData
    static final int FLAG_OFFSET                    = 32;
    static final int CREDENTIAL_ID_LENGTH_OFFSET    = FLAG_OFFSET + 1 + 4 + 16;
    
    static final CBORInt FWP_AUTHORIZATION_LABEL = FWPElements.AUTHORIZATION.cborLabel;
    
    public enum UserValidation {PRESENT, VERIFIED};


    public static byte[] addSignature(byte[] unsignedFwpAssertion,
                                      byte[] clientDataJSON,
                                      byte[] authenticatorData,
                                      byte[] signature) {
        if (clientDataJSON != null && 
            !Arrays.equals(HashAlgorithms.SHA256.digest(unsignedFwpAssertion),
                JSONParser.parse(clientDataJSON).getBinary(CHALLENGE))) {
            throw new CryptoException("Message hash mismatch");
        }
        CBORMap cborFwpAssertion = CBORDecoder.decode(unsignedFwpAssertion).getMap();
        CBORMap authorization = cborFwpAssertion.get(FWP_AUTHORIZATION_LABEL).getMap();
        authorization.set(AS_AUTHENTICATOR_DATA, new CBORBytes(authenticatorData))
                     .set(AS_SIGNATURE, new CBORBytes(signature));
        if (clientDataJSON != null) {
            authorization.set(AS_CLIENT_DATA_JSON, new CBORBytes(clientDataJSON));
        }
        return cborFwpAssertion.encode();
    }

    // For testing purposes only.
    static byte[] directSign(byte[] unsignedFwpAssertion, 
                             PrivateKey privateKey, 
                             String origin,
                             int flags,
                             boolean ctap2) {
        // Now we have the data needed for creating a FIDO ClientDataJSON object.
        try {
            byte[] clientDataJSON = ctap2 ? null : new JSONObjectWriter()
                .setString(CDJ_TYPE, CDJ_GET_ARGUMENT)
                .setString(CDJ_ORIGIN, origin)
                .setBinary(CHALLENGE, HashAlgorithms.SHA256.digest(unsignedFwpAssertion))
                .serializeToBytes(JSONOutputFormats.NORMALIZED);
            // Hard-coded FIDO Authenticator Data
            byte[] authenticatorData = Arrays.copyOf(
                        HashAlgorithms.SHA256.digest(UTF8.encode(new URL(origin).getHost())), 37);
            System.arraycopy(new byte[] {(byte)flags, 0, 0, 0, 23}, 0, authenticatorData, 32, 5);
       
            // Create a FIDO compatible signature.
            int coseAlgorithm = CBORDecoder.decode(unsignedFwpAssertion)
                .getMap().get(FWP_AUTHORIZATION_LABEL).getMap().get(AS_ALGORITHM).getInt32();
            byte[] signature = new SignatureWrapper(getWebPkiAlgorithm(coseAlgorithm), privateKey)
                // Weird, FIDO does not use the same ECDSA signature format as COSE and JOSE
                .ecdsaAsn1SignatureEncoding(true)
                .update(authenticatorData)
                .update(HashAlgorithms.SHA256.digest(ctap2 ? unsignedFwpAssertion : clientDataJSON))
                .sign();
            return addSignature(unsignedFwpAssertion, 
                                clientDataJSON,
                                authenticatorData, 
                                signature);
        } catch (GeneralSecurityException | IOException e) {
            throw new FWPException(e);
        }
    }

    public static class FWPPreSigner {

        CBORObject publicKey;

        public FWPPreSigner(byte[] cosePublicKey) {
            this.publicKey = CBORDecoder.decode(cosePublicKey);
        }

        CBORMap appendSignatureObject() {
            int coseAlgorithm = publicKey2CoseSignatureAlgorithm(CBORPublicKey.convert(publicKey));

            // Add the authorization container map including the members that
            // also are signed.
            return new CBORMap().set(AS_ALGORITHM, new CBORInt(coseAlgorithm))
                                .set(AS_PUBLIC_KEY, publicKey);
        }
    }


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
            return FIDO_KEYALG_RS256;
        }
        if (publicKey instanceof ECKey) {
            return FIDO_KEYALG_ES256;
        }
        // Waiting for an answer for how to deal with Ed448...
        return FIDO_KEYALG_ED25519;
    }

    /**
     * COSE algorithm to WebPKI algorithm.
     * 
     * @param coseAlgorithm COSE signature algorithm
     * @return WebPKI signature algorithm
     */
    public static AsymSignatureAlgorithms getWebPkiAlgorithm(int coseAlgorithm) {
        switch (coseAlgorithm) {
            case FIDO_KEYALG_RS256:
                return AsymSignatureAlgorithms.RSA_SHA256;
    
            case  FIDO_KEYALG_ES256:
                return AsymSignatureAlgorithms.ECDSA_SHA256;
            
            case FIDO_KEYALG_ED25519:
                // Well, this is not really COSE but who cares?
                return AsymSignatureAlgorithms.ED25519;
    
            default:
                throw new CryptoException("Unexpected signature algorithm: " + coseAlgorithm);
        }
    }
    
    private static void algorithmComplianceTest(PublicKey publicKey, int coseAlgorithm) {
        if (publicKey2CoseSignatureAlgorithm(publicKey) != coseAlgorithm) {
            throw new CryptoException("Algorithm ("  + coseAlgorithm + 
                    ") does not match public key type: " + publicKey.getAlgorithm());
        }
    }
    
    /**
     * Validate FIDO signature.
     * 
     * @param algorithm Signature algorithm in WebPKI notation
     * @param publicKey Public key in Java format
     * @param authenticatorData FIDO core data
     * @param clientData FIDO application data
     * @param signature FIDO core data
     */
    public static void validateFidoSignature(AsymSignatureAlgorithms algorithm, 
                                             PublicKey publicKey,
                                             byte[] authenticatorData,
                                             byte[] clientData,
                                             byte[] signature) {
        try {
            if (!new SignatureWrapper(algorithm, publicKey)
                // Weird, FIDO does not use the same ECDSA signature format as COSE and JOSE
                .ecdsaAsn1SignatureEncoding(true)
                .update(authenticatorData)
                // Creating clientDataHash
                .update(HashAlgorithms.SHA256.digest(clientData))
                .verify(signature)) {
                throw new GeneralSecurityException("Signature validation failed");
            }
        } catch (GeneralSecurityException e) {
            throw new CryptoException(e);
        }
    }
    
    /**
     * Validate FWP assertion with respect to crypto.
     *
     * Exclusively called by FWPAssertionDecoder
     * @param fwpAssertion FWP assertion
     * @param userValidationFlags From the authenticator
     * @return Public key in COSE format
     */
    static byte[] validateFwpSignature(CBORMap fwpAssertion,
                                       HashSet<UserValidation> userValidationFlags) {
        // Retrieve the authorization object.
        CBORMap authorization = fwpAssertion.get(FWP_AUTHORIZATION_LABEL).getMap();
        
        // Fetch the core FIDO assertion elements. Remove them
        // from the FWP assertion as well since they are not a
        // part of the FIDO "challenge" data.
        byte[] authenticatorData = authorization.remove(AS_AUTHENTICATOR_DATA).getBytes();
        // Note that the ctap2 option removes "clientDataJSON" from FWP assertions.
        boolean ctap2 = !authorization.containsKey(AS_CLIENT_DATA_JSON);
        byte[] clientDataJSON = 
                ctap2 ? null : authorization.remove(AS_CLIENT_DATA_JSON).getBytes();
        byte[] signature = authorization.remove(AS_SIGNATURE).getBytes();
        
        // Collect authenticator data that may be useful in disputes.
        // Note that possible extension data (ED) is ignored.
        if ((authenticatorData[FLAG_OFFSET] & FLAG_UP) != 0) {
            userValidationFlags.add(UserValidation.PRESENT);
        }
        if ((authenticatorData[FLAG_OFFSET] & FLAG_UV) != 0) {
            userValidationFlags.add(UserValidation.VERIFIED);
        }        

        // The public key must be available and be in COSE format.
        // Here it is converted to the Java format since this
        // is necessary for validation using Java standard tools.
        CBORObject cborPublicKey = authorization.get(AS_PUBLIC_KEY);
        PublicKey publicKey = CBORPublicKey.convert(cborPublicKey);
        
        // The mandatory COSE signature algorithm.
        int coseAlgorithm = authorization.get(AS_ALGORITHM).getInt32();
        
        // Does the algorithm match the public key?
        algorithmComplianceTest(publicKey, coseAlgorithm);
        
        // This is not WebAuthn, this is FIDO Web Pay: 
        if (!ctap2 && !Arrays.equals(HashAlgorithms.SHA256.digest(fwpAssertion.encode()),
                                     JSONParser.parse(clientDataJSON).getBinary(CHALLENGE))) {
            throw new CryptoException("Message hash mismatch");
        }
        
        // Everything is good so far, now take on the core FIDO signature.
        validateFidoSignature(getWebPkiAlgorithm(coseAlgorithm),
                              publicKey,
                              authenticatorData,
                              ctap2 ? fwpAssertion.encode() : clientDataJSON,
                              signature);

        // Return the "raw" public key for looking up in an RP database.
        return cborPublicKey.encode();
    }
    
    /**
     * 
     * Return class for credential data
     *
     */
    
    public static class UserCredential {
        public byte[] credentialId;
        public byte[] rawCosePublicKey;
    }

    /**
     * Extract user credential data from a FIDO attestation.
     * 
     * @param attestationObject Created by the registration call
     * @return Public key in COSE format
     */
    public static UserCredential extractUserCredential(byte[] attestationObject) {
        
        // Creating output structure
        UserCredential userCredential = new UserCredential();

        // Digging out the COSE public key is somewhat awkward...
        byte[] authData = CBORDecoder.decode(attestationObject)
                .getMap().get(AUTH_DATA_CBOR).getBytes();
        if ((authData[FLAG_OFFSET] & FLAG_AT) == 0) {
            throw new CryptoException("Unsupported authData flags: 0x" + 
                                      String.format("%2x", authData[FLAG_OFFSET] & 0xff));
        }

        // Get credentialId.
        int credentialIdLength = (authData[CREDENTIAL_ID_LENGTH_OFFSET] << 8) + 
                (authData[CREDENTIAL_ID_LENGTH_OFFSET + 1] & 0xff);
        userCredential.credentialId = new byte[credentialIdLength];
        int offset = CREDENTIAL_ID_LENGTH_OFFSET + 2;
        for (int q = 0; q < credentialIdLength; ) {
            userCredential.credentialId[q++] = authData[offset++];
        }

        // We silently drop possible Extension Data (ED).
        int maxLength = authData.length - offset;
        CBORMap fidoPublicKey = 
            new CBORDecoder(new ByteArrayInputStream(authData, offset, maxLength))
                .setSequenceMode(true)
                .setInputLength(maxLength).decodeWithOptions().getMap();

        // Fetch the signature algorithm but remove it from the public key object.
        int signatureAlgorithm = fidoPublicKey.get(COSE_ALGORITHM_LABEL).getInt32();
        fidoPublicKey.remove(COSE_ALGORITHM_LABEL);

        // Verify that we got a genuine FIDO/COSE public key and
        // that the associated signature algorithm matches.
        PublicKey publicKey = CBORPublicKey.convert(fidoPublicKey);
        algorithmComplianceTest(publicKey, signatureAlgorithm);
        
        // Back to black (raw) :)
        userCredential.rawCosePublicKey = fidoPublicKey.encode();
        
        // Return all.
        return userCredential;
    }
}
