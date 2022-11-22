/*
 *  Copyright 2006-2021 WebPKI.org (http://webpki.org).
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

import java.io.File;
import java.io.IOException;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

import java.util.Base64;
import java.util.GregorianCalendar;

import org.webpki.cbor.CBORAsymKeyDecrypter;
import org.webpki.cbor.CBORAsymKeyEncrypter;
import org.webpki.cbor.CBORMap;
import org.webpki.cbor.CBORObject;
import org.webpki.cbor.CBORPublicKey;
import org.webpki.cbor.CBORTextString;

import org.webpki.crypto.CustomCryptoProvider;
import org.webpki.crypto.HashAlgorithms;
import org.webpki.crypto.ContentEncryptionAlgorithms;
import org.webpki.crypto.KeyEncryptionAlgorithms;

import org.webpki.jose.JOSEKeyWords;

import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONOutputFormats;
import org.webpki.json.JSONParser;

import org.webpki.util.ArrayUtil;
import org.webpki.util.HexaDecimal;
import org.webpki.util.ISODateTime;

/**
 * Create FWP test vectors.
 */
public class TestVectorGeneration {
    
    static final boolean ctap2 = true;
    
    static final Base64.Encoder Base64UrlEncoder = Base64.getUrlEncoder().withoutPadding();
    
    static final String ISSUER_URL     = "https://mybank.fr";
    static final String ISSUER_ID      = "https://mybank.fr/payment";
    static final String PAYMENT_METHOD = "https://banknet2.org";
    static final CBORTextString ISSUER_KEY_ID = new CBORTextString("x25519:2022:1");

    static final KeyEncryptionAlgorithms ISSUER_KEY_ENCRYPTION_ALGORITHM =
            KeyEncryptionAlgorithms.ECDH_ES_A256KW;
    static final ContentEncryptionAlgorithms ISSUER_CONTENT_ENCRYPTION_ALGORITHM =
            ContentEncryptionAlgorithms.A256GCM;


    static final String MERCHANT_HOST = "spaceshop.com";
    
    static final String FILE_TESTVECTOR_TEXT = "vectors.txt";
    
    static final String FILE_SIGNATURE_JWK   = "signature.jwk";
    static final String FILE_ENCRYPTION_JWK  = "encryption.jwk";
    static final String FILE_UNSIGNED_CBOR   = "ad.cbor";
    static final String FILE_SIGNED_CBOR     = "sad.cbor";
    static final String FILE_ENCRYPTED_CBOR  = "esad.cbor";
    static final String FILE_CHALLENGE_B64U  = "challenge.txt";
    static final String FILE_CLIENT_DATA_JSON  = "clientDataJSON.json";
    static final String FILE_FWP_ASSERTION_JSON  = "FWP-assertion.json";
    static final String FILE_PSP_REQUEST_JSON  = "PSP-request.json";
    static final String FILE_ISSUER_REQUEST_JSON  = "ISSUER-request.json";

    String testDataDir;
    String keyDir;
    
    String currPrivateKey;
    
    boolean signRewrite;
    
    StringBuilder result = new StringBuilder("|===================================|\n" +
                                             "| FIDO Web Pay (FWP) - Test Vectors |\n" +
                                             "|===================================|\n\n");
    
    KeyPair readKey(String keyAlg) throws IOException, GeneralSecurityException {
        JSONObjectReader key = 
                JSONParser.parse(ArrayUtil.readFile(keyDir + keyAlg + "privatekey.jwk"));
        key.removeProperty(JOSEKeyWords.KID_JSON);
        currPrivateKey = key.toString();
        return key.getKeyPair();
    }
    

    TestVectorGeneration(String testDataDir, String keyDir) throws IOException,
                                                                   GeneralSecurityException {
        this.testDataDir = testDataDir;
        this.keyDir = keyDir;
            
        KeyPair p256 = readKey("p256");
        result.append("\n\nUser FIDO key in JWK format:\n")
              .append(currPrivateKey);

        conditionalRewrite(testDataDir + FILE_SIGNATURE_JWK, 
                currPrivateKey.getBytes("utf-8"));

        GregorianCalendar time = ISODateTime.parseDateTime("2022-08-18T10:14:07+01:00",
                                                           ISODateTime.LOCAL_NO_SUBSECONDS);
        
        FWPCrypto.FWPPreSigner fwpSigner =
                new FWPCrypto.FWPPreSigner(CBORPublicKey.encode(p256.getPublic()).encode());
       
        FWPPaymentRequest paymentRequest = 
                new FWPPaymentRequest("Space Shop", "7040566321", "435.00", "EUR");
        
        result.append("\n\nMerchant 'W3C PaymentRequest' (PRCD) data in " +
                      "pretty-printed JSON notation:\n")
              .append(paymentRequest.toString())
              .append("\nMerchant 'hostname' according to the browser: " + MERCHANT_HOST);
        
        byte[] unsignedFwpAssertion = new FWPAssertionBuilder()
                .setPaymentRequest(paymentRequest)
                .setOptionalTimeStamp(time)
                .setPaymentInstrumentData("FR7630002111110020050014382",
                                          "0057162932",
                                          PAYMENT_METHOD)
                .setPlatformData("Android", "10.0", "Chrome", "103")
                .setNetworkOptions("\"additional stuff...\"")
                .setPayeeHost(MERCHANT_HOST)
                .create(fwpSigner);
        
        byte[] fwpAssertion = 
                FWPCrypto.directSign(unsignedFwpAssertion,
                                     p256.getPrivate(),
                                     ISSUER_URL,
                                     FWPCrypto.FLAG_UP + FWPCrypto.FLAG_UV,
                                     ctap2);

        // ES256 generates different results for each round.  We try to limit that...
        fwpAssertion = optionalSignatureRewrite(testDataDir + FILE_SIGNED_CBOR, fwpAssertion);
        CBORMap authContainer = CBORObject.decode(fwpAssertion).getMap().getObject(
                FWPCrypto.FWP_AUTHORIZATION_LABEL).getMap();

        result.append("\n\n\nUnsigned FWP assertion, here in CBOR 'diagnostic notation':\n")
              .append(CBORObject.decode(unsignedFwpAssertion).toString())
              .append("\n\nNote that the last element (")
              .append(FWPElements.AUTHORIZATION.cborLabel)
              .append(") contains the COSE signature algorithm (ES256) and " +
                      "the FIDO public key (EC/P256) which is " +
                      "also is part of the data to be signed.\n");
        String challengeB64U = Base64UrlEncoder.encodeToString(
                HashAlgorithms.SHA256.digest(unsignedFwpAssertion));

        conditionalRewrite(testDataDir + FILE_CHALLENGE_B64U, 
                challengeB64U.getBytes("utf-8"));

        result.append("\n\nThe unsigned FWP assertion (binary) " +
                      "converted into a SHA256 hash, here in Base64Url notation:\n")
              .append(challengeB64U)
              .append("\nThis is subsequently used as FIDO 'challenge'.\n\n\n" +
                      "****************************************\n" +
                      "* FIDO/WebAuthn assertion happens here *\n" +
                      "****************************************");
        
        byte[] clientDataJSONbin = ctap2 ? null : authContainer.getObject(
                FWPCrypto.AS_CLIENT_DATA_JSON).getByteString();
  
        if (!ctap2) {
            conditionalRewrite(testDataDir + FILE_CLIENT_DATA_JSON, 
                    clientDataJSONbin);
    
            JSONObjectReader clientDataJSON = JSONParser.parse(clientDataJSONbin);
    
            result.append("\n\nReturned FIDO '" + FWPCrypto.CLIENT_DATA_JSON + 
                          "', here shown in clear:\n")
                  .append(clientDataJSON.serializeToString(JSONOutputFormats.NORMALIZED));
        }
        
        result.append("\nRelying party URL: " + ISSUER_URL + "\n" +
                      "\nReturned FIDO '" + FWPCrypto.AUTHENTICATOR_DATA + 
                      "' in hexadecimal notation:\n")
              .append(HexaDecimal.encode(
                      authContainer.getObject(FWPCrypto.AS_AUTHENTICATOR_DATA).getByteString()))
              .append("\n(here using the UP+UV flags and a zero counter value)\n");

        result.append("\nReturned FIDO '" + FWPCrypto.SIGNATURE + 
                      "' in hexadecimal notation:\n")
        .append(HexaDecimal.encode(
              authContainer.getObject(FWPCrypto.AS_SIGNATURE).getByteString()));

        result.append("\n\nSigned FWP assertion (SAD), here in CBOR 'diagnostic notation':\n")
              .append(CBORObject.decode(fwpAssertion).toString())
              .append("\n\nThe added elements " + FWPCrypto.AS_AUTHENTICATOR_DATA +
                      "," + FWPCrypto.AS_CLIENT_DATA_JSON +
                      "," + FWPCrypto.AS_SIGNATURE +
                      (ctap2 ? "" : " represent FIDO's '" + FWPCrypto.AUTHENTICATOR_DATA) +
                      "','" +FWPCrypto.CLIENT_DATA_JSON +
                      "' and '" +  FWPCrypto.SIGNATURE + 
                      "' respectively.\n")
              .append("\n\nThe signed FWP assertion as a hex-encoded binary: ")
              .append(HexaDecimal.encode(fwpAssertion));

  
        if (conditionalRewrite(testDataDir + FILE_UNSIGNED_CBOR, unsignedFwpAssertion)) {
            writeTextVersion(FILE_UNSIGNED_CBOR, unsignedFwpAssertion);
        }
        
        KeyPair x25519 = readKey("x25519");
        result.append("\n\n\n" +
                      "*******************************\n" +
                      "* FWP encryption happens here *\n" +
                      "*******************************" +

                      "\n\nIssuer encryption key in JWK format:\n")
              .append(currPrivateKey);

        conditionalRewrite(testDataDir + FILE_ENCRYPTION_JWK, 
                currPrivateKey.getBytes("utf-8"));
        
        byte[] encryptedAssertion = 
                new CBORAsymKeyEncrypter(x25519.getPublic(),
                                         ISSUER_KEY_ENCRYPTION_ALGORITHM,
                                         ISSUER_CONTENT_ENCRYPTION_ALGORITHM)
                .setKeyId(ISSUER_KEY_ID).encrypt(fwpAssertion).encode();
        if (!signRewrite) {
            try {
                encryptedAssertion = ArrayUtil.readFile(testDataDir + FILE_ENCRYPTED_CBOR);
            } catch (Exception e) {
                signRewrite = true;
            }
        }
        if (signRewrite) {
            ArrayUtil.writeFile(testDataDir + FILE_ENCRYPTED_CBOR, encryptedAssertion);
            writeTextVersion(FILE_ENCRYPTED_CBOR, encryptedAssertion);
        }
        
        result.append("\n\nEncrypted FWP assertion (ESAD), here in CBOR 'diagnostic notation:\n")
              .append(CBORObject.decode(encryptedAssertion).toString())
              .append("\n\nAnd as a hex-encoded binary: ")
              .append(HexaDecimal.encode(encryptedAssertion))
              .append("\n");
        
        FWPJsonAssertion fwpJsonAssertion = new FWPJsonAssertion(PAYMENT_METHOD,
                ISSUER_ID,
                encryptedAssertion);
        result.append("\n\nFWP assertion delivered by the browser:\n")
              .append(fwpJsonAssertion.toString());

        conditionalRewrite(testDataDir + FILE_FWP_ASSERTION_JSON, 
                           fwpJsonAssertion.toString().getBytes("utf-8"));

        byte[] decryptedFwpAssertion = 
                new CBORAsymKeyDecrypter(new CBORAsymKeyDecrypter.KeyLocator() {
            
            @Override
            public PrivateKey locate(PublicKey optionalPublicKey,
                                     CBORObject optionalKeyId,
                                     KeyEncryptionAlgorithms keyEncryptionAlgorithm,
                                     ContentEncryptionAlgorithms contentEncryptionAlgorithm) 
                    throws IOException, GeneralSecurityException {
                if (!ISSUER_KEY_ID.equals(optionalKeyId)) {
                    throw new GeneralSecurityException("Wrong/missing ID");
                }
                return x25519.getPrivate();
            }
        }).decrypt(CBORObject.decode(encryptedAssertion));
 
        FWPAssertionDecoder decodedFwpAssertion =
                new FWPAssertionDecoder(decryptedFwpAssertion);
        decodedFwpAssertion.verifyClaimedPaymentRequest(paymentRequest);

        conditionalRewrite(testDataDir + FILE_TESTVECTOR_TEXT, 
                           result.toString().getBytes("utf-8"));

        
        // The following were only added for the specification samples...
        
        time.add(GregorianCalendar.SECOND, 15);
        PSPRequest pspRequest = new PSPRequest(paymentRequest,
                                               fwpJsonAssertion, 
                                               "DE89370400440532013000", 
                                               "220.13.198.144", 
                                               time);
        conditionalRewrite(testDataDir + FILE_PSP_REQUEST_JSON, 
                pspRequest.toString().getBytes("utf-8"));

        
        time.add(GregorianCalendar.SECOND, 1);
        IssuerRequest issuerRequest = new IssuerRequest(pspRequest,
                                                        "spaceshop.com", 
                                                        time);
        conditionalRewrite(testDataDir + FILE_ISSUER_REQUEST_JSON, 
                issuerRequest.toString().getBytes("utf-8"));

    }

    boolean conditionalRewrite(String fileName, byte[] newFile) throws IOException {
        try {
            byte[] oldFile = ArrayUtil.readFile(fileName);
            if (ArrayUtil.compare(oldFile, newFile)) {
                return false;
            }
        } catch (Exception e) {
            
        }
        ArrayUtil.writeFile(fileName, newFile);
        return true;
    }


    CBORMap cleanSignature(byte[] assertion) throws IOException {
        CBORMap fwpAssertion = CBORObject.decode(assertion).getMap();
        fwpAssertion.getObject(FWPElements.AUTHORIZATION.cborLabel)
        .getMap().removeObject(FWPCrypto.AS_SIGNATURE);
        return fwpAssertion;
    }
    
    private byte[] optionalSignatureRewrite(String fileName, 
                                            byte[] fwpAssertion) throws IOException {
        try {
            byte[] oldFwpAssertion = ArrayUtil.readFile(fileName);
            if (cleanSignature(oldFwpAssertion).equals(cleanSignature(fwpAssertion))) {
                return oldFwpAssertion;
            }
        } catch (IOException e) {
            
        }
        signRewrite = true;
        ArrayUtil.writeFile(testDataDir + FILE_SIGNED_CBOR, fwpAssertion);
        writeTextVersion(FILE_SIGNED_CBOR, fwpAssertion);
        return fwpAssertion;
    }


    private void writeTextVersion(String fileSignedCbor, 
                                  byte[] fwpAssertion) throws IOException {
        ArrayUtil.writeFile(testDataDir + fileSignedCbor.toUpperCase()
                .substring(0, fileSignedCbor.length() - 4) + "txt",
                            CBORObject.decode(fwpAssertion).toString().getBytes("utf-8"));
    }


    public static void main(String[] args) {
        try {
            CustomCryptoProvider.forcedLoad(false);
           new TestVectorGeneration(args[0] + File.separatorChar,
                                    args[1] + File.separatorChar);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
