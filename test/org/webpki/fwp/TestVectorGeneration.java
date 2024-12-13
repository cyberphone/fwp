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

import java.util.Arrays;
import java.util.GregorianCalendar;

import org.webpki.cbor.CBORAsymKeyDecrypter;
import org.webpki.cbor.CBORAsymKeyEncrypter;
import org.webpki.cbor.CBORCryptoUtils;
import org.webpki.cbor.CBORDecoder;
import org.webpki.cbor.CBORMap;
import org.webpki.cbor.CBORObject;
import org.webpki.cbor.CBORPublicKey;
import org.webpki.cbor.CBORTag;
import org.webpki.cbor.CBORString;

import org.webpki.crypto.HashAlgorithms;
import org.webpki.crypto.ContentEncryptionAlgorithms;
import org.webpki.crypto.CryptoException;
import org.webpki.crypto.KeyEncryptionAlgorithms;

import org.webpki.jose.JOSEKeyWords;

import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONOutputFormats;
import org.webpki.json.JSONParser;

import org.webpki.util.Base64URL;
import org.webpki.util.HexaDecimal;
import org.webpki.util.IO;
import org.webpki.util.ISODateTime;
import org.webpki.util.UTF8;

/**
 * Create FWP test vectors.
 */
public class TestVectorGeneration {
    
    static final boolean ctap2 = true;
    
    static final String ISSUER_URL     = "https://mybank.fr";
    static final String ISSUER_ID      = "https://mybank.fr/payment";
    static final String PAYMENT_METHOD = "https://banknet2.org";
    static final CBORString ISSUER_KEY_ID = new CBORString("x25519:2022:1");

    static final KeyEncryptionAlgorithms ISSUER_KEY_ENCRYPTION_ALGORITHM =
            KeyEncryptionAlgorithms.ECDH_ES_A256KW;
    static final ContentEncryptionAlgorithms ISSUER_CONTENT_ENCRYPTION_ALGORITHM =
            ContentEncryptionAlgorithms.A256GCM;


    static final String MERCHANT_HOST = "spaceshop.com";
    
    static final String FILE_TESTVECTOR_TEXT = "vectors.txt";
    
    static final String FILE_SIGNATURE_JWK   = "signature.jwk";
    static final String FILE_ENCRYPTION_JWK  = "encryption.jwk";
    static final String FILE_UNSIGNED_CBOR   = "ad.cbor";
    static final String FILE_HASHED_BIN     = "hashed-AD.bin";
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
                JSONParser.parse(IO.readFile(keyDir + keyAlg + "privatekey.jwk"));
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
                UTF8.encode(currPrivateKey));

        GregorianCalendar time = ISODateTime.decode("2023-02-16T10:14:07+01:00",
                                                    ISODateTime.LOCAL_NO_SUBSECONDS);
        
        FWPCrypto.FWPPreSigner fwpSigner =
                new FWPCrypto.FWPPreSigner(CBORPublicKey.convert(p256.getPublic()).encode());
       
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
                .setPlatformData("Android", "12.0", "Chrome", "108")
                .setNetworkOptions("\"additional stuff...\"")
                .setPayeeHost(MERCHANT_HOST)
                .setLocation(40.748440, -73.984559)  // Empire State Building
                .create(fwpSigner);
        
        conditionalRewrite(testDataDir + FILE_HASHED_BIN, 
                HashAlgorithms.SHA256.digest(unsignedFwpAssertion));

        byte[] fwpAssertion = 
                FWPCrypto.directSign(unsignedFwpAssertion,
                                     p256.getPrivate(),
                                     ISSUER_URL,
                                     FWPCrypto.FLAG_UP + FWPCrypto.FLAG_UV,
                                     ctap2);

        // ES256 generates different results for each round.  We try to limit that...
        fwpAssertion = optionalSignatureRewrite(testDataDir + FILE_SIGNED_CBOR, fwpAssertion);
        CBORMap authContainer = CBORDecoder.decode(fwpAssertion).getMap().get(
                FWPCrypto.FWP_AUTHORIZATION_LABEL).getMap();

        result.append("\n\n\nUnsigned FWP assertion, here in CBOR 'diagnostic notation':\n")
              .append(CBORDecoder.decode(unsignedFwpAssertion).toString())
              .append("\n\nNote that the last element (")
              .append(FWPElements.AUTHORIZATION.cborLabel)
              .append(") contains the COSE signature algorithm (ES256) and " +
                      "the FIDO public key (EC/P256) which is " +
                      "also is part of the data to be signed.\n");
        String challengeB64U = Base64URL.encode(
                HashAlgorithms.SHA256.digest(unsignedFwpAssertion));

        conditionalRewrite(testDataDir + FILE_CHALLENGE_B64U, 
                UTF8.encode(challengeB64U));

        result.append("\n\nThe unsigned FWP assertion (binary) " +
                      "converted into a SHA256 hash, here in Base64Url notation:\n")
              .append(challengeB64U)
              .append("\nThis is subsequently used as FIDO 'challenge'.\n\n\n" +
                      "****************************************\n" +
                      "* FIDO/WebAuthn assertion happens here *\n" +
                      "****************************************");
        
        byte[] clientDataJSONbin = ctap2 ? null : authContainer.get(
                FWPCrypto.AS_CLIENT_DATA_JSON).getBytes();
  
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
                      authContainer.get(FWPCrypto.AS_AUTHENTICATOR_DATA).getBytes()))
              .append("\n(here using the UP+UV flags and a zero counter value)\n");

        result.append("\nReturned FIDO '" + FWPCrypto.SIGNATURE + 
                      "' in hexadecimal notation:\n")
        .append(HexaDecimal.encode(
              authContainer.get(FWPCrypto.AS_SIGNATURE).getBytes()));

        result.append("\n\nSigned FWP assertion (SAD), here in CBOR 'diagnostic notation':\n")
              .append(CBORDecoder.decode(fwpAssertion).toString())
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
                UTF8.encode(currPrivateKey));
        
        byte[] encryptedAssertion = 
                new CBORAsymKeyEncrypter(x25519.getPublic(),
                                         ISSUER_KEY_ENCRYPTION_ALGORITHM,
                                         ISSUER_CONTENT_ENCRYPTION_ALGORITHM)
                .setKeyId(ISSUER_KEY_ID)
                .setIntercepter(new CBORCryptoUtils.Intercepter() {

                    @Override
                    public CBORObject wrap(CBORMap unwrappedMap) {
                        return new CBORTag(FWPCrypto.FWP_ESAD_OBJECT_ID, unwrappedMap);
                    }
                }).encrypt(fwpAssertion).encode();
        if (!signRewrite) {
            try {
                encryptedAssertion = IO.readFile(testDataDir + FILE_ENCRYPTED_CBOR);
            } catch (Exception e) {
                signRewrite = true;
            }
        }
        if (signRewrite) {
            IO.writeFile(testDataDir + FILE_ENCRYPTED_CBOR, encryptedAssertion);
            writeTextVersion(FILE_ENCRYPTED_CBOR, encryptedAssertion);
        }
        
        result.append("\n\nEncrypted FWP assertion (ESAD), here in CBOR 'diagnostic notation:\n")
              .append(CBORDecoder.decode(encryptedAssertion).toString())
              .append("\n\nAnd as a hex-encoded binary: ")
              .append(HexaDecimal.encode(encryptedAssertion))
              .append("\n");
        
        FWPJsonAssertion fwpJsonAssertion = new FWPJsonAssertion(PAYMENT_METHOD,
                ISSUER_ID,
                encryptedAssertion);
        result.append("\n\nFWP assertion delivered by the browser:\n")
              .append(fwpJsonAssertion.toString());

        conditionalRewrite(testDataDir + FILE_FWP_ASSERTION_JSON, 
                           UTF8.encode(fwpJsonAssertion.toString()));

        byte[] decryptedFwpAssertion = 
                new CBORAsymKeyDecrypter(new CBORAsymKeyDecrypter.KeyLocator() {
                    
            @Override
            public PrivateKey locate(PublicKey optionalPublicKey,
                                     CBORObject optionalKeyId,
                                     KeyEncryptionAlgorithms keyEncryptionAlgorithm,
                                     ContentEncryptionAlgorithms contentEncryptionAlgorithm) {
                if (!ISSUER_KEY_ID.equals(optionalKeyId)) {
                    throw new CryptoException("Wrong/missing ID");
                }
                return x25519.getPrivate();
            }
          
        }).setTagPolicy(CBORCryptoUtils.POLICY.MANDATORY, new CBORCryptoUtils.Collector() {
            
            @Override
            public void foundData(CBORObject tag) {
                String typeUrl = tag.getTag().get().getArray().get(0).getString();
                if (!FWPCrypto.FWP_ESAD_OBJECT_ID.equals(typeUrl)) {
                    throw new CryptoException("Unexpected type URL: " + typeUrl);
                }
            }

        }).decrypt(CBORDecoder.decode(encryptedAssertion));
 
        FWPAssertionDecoder decodedFwpAssertion =
                new FWPAssertionDecoder(decryptedFwpAssertion);
        decodedFwpAssertion.verifyClaimedPaymentRequest(paymentRequest);

        conditionalRewrite(testDataDir + FILE_TESTVECTOR_TEXT, 
                           result.toString());

        
        // The following were only added for the specification samples...
        
        time.add(GregorianCalendar.SECOND, 15);
        PSPRequest pspRequest = new PSPRequest(paymentRequest,
                                               fwpJsonAssertion, 
                                               "DE89370400440532013000", 
                                               "220.13.198.144", 
                                               time);
        conditionalRewrite(testDataDir + FILE_PSP_REQUEST_JSON, 
                pspRequest.toString());

        
        time.add(GregorianCalendar.SECOND, 1);
        IssuerRequest issuerRequest = new IssuerRequest(pspRequest,
                                                        "spaceshop.com", 
                                                        time);
        conditionalRewrite(testDataDir + FILE_ISSUER_REQUEST_JSON, 
                issuerRequest.toString());

    }

    boolean conditionalRewrite(String fileName, byte[] newFile) throws IOException {
        try {
            byte[] oldFile = IO.readFile(fileName);
            if (Arrays.equals(oldFile, newFile)) {
                return false;
            }
        } catch (Exception e) {
            
        }
        IO.writeFile(fileName, newFile);
        return true;
    }

    boolean conditionalRewrite(String fileName, String newFile) throws IOException {
        return conditionalRewrite(fileName, UTF8.encode(newFile));
    }

    CBORMap cleanSignature(byte[] assertion) throws IOException {
        CBORMap fwpAssertion = CBORDecoder.decode(assertion).getMap();
        fwpAssertion.get(FWPElements.AUTHORIZATION.cborLabel)
        .getMap().remove(FWPCrypto.AS_SIGNATURE);
        return fwpAssertion;
    }
    
    private byte[] optionalSignatureRewrite(String fileName, 
                                            byte[] fwpAssertion) throws IOException {
        try {
            byte[] oldFwpAssertion = IO.readFile(fileName);
            if (cleanSignature(oldFwpAssertion).equals(cleanSignature(fwpAssertion))) {
                return oldFwpAssertion;
            }
        } catch (IOException e) {
            
        }
        signRewrite = true;
        IO.writeFile(testDataDir + FILE_SIGNED_CBOR, fwpAssertion);
        writeTextVersion(FILE_SIGNED_CBOR, fwpAssertion);
        return fwpAssertion;
    }


    private void writeTextVersion(String fileSignedCbor, 
                                  byte[] fwpAssertion) throws IOException {
        IO.writeFile(testDataDir + fileSignedCbor.toUpperCase()
                .substring(0, fileSignedCbor.length() - 4) + "txt",
                CBORDecoder.decode(fwpAssertion).toString());
    }


    public static void main(String[] args) {
        try {
           new TestVectorGeneration(args[0] + File.separatorChar,
                                    args[1] + File.separatorChar);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
