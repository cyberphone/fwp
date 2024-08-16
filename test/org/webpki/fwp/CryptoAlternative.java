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

import java.util.GregorianCalendar;
import java.util.HashMap;

import org.webpki.cbor.CBORAsymKeyDecrypter;
import org.webpki.cbor.CBORAsymKeyEncrypter;
import org.webpki.cbor.CBORCryptoUtils;
import org.webpki.cbor.CBORDecoder;
import org.webpki.cbor.CBORDecrypter;
import org.webpki.cbor.CBORMap;
import org.webpki.cbor.CBORObject;
import org.webpki.cbor.CBORPublicKey;
import org.webpki.cbor.CBORTag;
import org.webpki.cbor.CBORString;

import org.webpki.crypto.EncryptionCore;
import org.webpki.crypto.ContentEncryptionAlgorithms;
import org.webpki.crypto.CryptoException;
import org.webpki.crypto.KeyEncryptionAlgorithms;

import org.webpki.jose.JOSEKeyWords;

import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONParser;
import org.webpki.util.IO;
import org.webpki.util.ISODateTime;

/**
 * An alternative SAD/ESAD solution.
 */
public class CryptoAlternative {
    
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
    
    static final String FILE_CRYPTO_ALTERNATIVE_TEXT = "crypto-alternative.txt";
    
    String testDataDir;
    String keyDir;
    
    String currPrivateKey;
    
    StringBuilder result = new StringBuilder("|==============================|\n" +
                                             "| Alternaive SAD/ESAD solution |\n" +
                                             "|==============================|\n\n");
    
    KeyPair readKey(String keyAlg) throws IOException, GeneralSecurityException {
        JSONObjectReader key = 
                JSONParser.parse(IO.readFile(keyDir + keyAlg + "privatekey.jwk"));
        key.removeProperty(JOSEKeyWords.KID_JSON);
        currPrivateKey = key.toString();
        return key.getKeyPair();
    }
    

    CryptoAlternative(String testDataDir, String keyDir) throws IOException,
                                                                   GeneralSecurityException {
        this.testDataDir = testDataDir;
        this.keyDir = keyDir;
            
        KeyPair p256 = readKey("p256");
        result.append("\n\nUser FIDO key in JWK format:\n")
              .append(currPrivateKey);

        GregorianCalendar time = ISODateTime.decode("2023-02-16T10:14:07+01:00",
                                                    ISODateTime.LOCAL_NO_SUBSECONDS);
        
        FWPCrypto.FWPPreSigner fwpSigner =
                new FWPCrypto.FWPPreSigner(CBORPublicKey.convert(p256.getPublic()).encode());
       
        FWPPaymentRequest paymentRequest = 
                new FWPPaymentRequest("Space Shop", "7040566321", "435.00", "EUR");
        
        result.append("\n\nMerchant 'W3C PaymentRequest' (PRCD) data:\n")
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
        
        byte[] fwpAssertion = 
                FWPCrypto.directSign(unsignedFwpAssertion,
                                     p256.getPrivate(),
                                     ISSUER_URL,
                                     FWPCrypto.FLAG_UP + FWPCrypto.FLAG_UV,
                                     ctap2);
        
        result.append("\n\nSigned FWP assertion (SAD):\n")
              .append(CBORDecoder.decode(fwpAssertion).toString());
        
        CBORMap cborTemp = CBORDecoder.decode(fwpAssertion).getMap();

        CBORObject cborPaymentRequest = cborTemp.remove(FWPElements.PAYMENT_REQUEST.cborLabel);
        fwpAssertion = cborTemp.encode();

        result.append("\n\nSigned FWP assertion (SAD) after PRCD removal:\n")
        .append(CBORDecoder.decode(fwpAssertion).toString());
  
        
        KeyPair x25519 = readKey("x25519");
        result.append("\n\n\n" +
                      "*******************************\n" +
                      "* FWP encryption happens here *\n" +
                      "*******************************" +

                      "\n\nIssuer encryption key in JWK format:\n")
              .append(currPrivateKey);

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

                    @Override
                    public CBORObject getCustomData() {
                        return cborPaymentRequest;
                    }

                }).encrypt(fwpAssertion).encode();
        
        result.append("\n\nEncrypted FWP assertion (ESAD):\n")
              .append(CBORDecoder.decode(encryptedAssertion).toString());
        
        HashMap<CBORObject, PrivateKey> keys = new HashMap<>();
        keys.put(ISSUER_KEY_ID, x25519.getPrivate());
        ProcessFwpAssertion.setDecryptionKeys(keys);
        new ProcessFwpAssertion(encryptedAssertion);

/* 
                 decodedFwpAssertion.verifyClaimedPaymentRequest(paymentRequest);
        
*/
        IO.writeFile(testDataDir + FILE_CRYPTO_ALTERNATIVE_TEXT, result.toString());
    }

       
    public static void main(String[] args) {
        try {
           new CryptoAlternative(args[0] + File.separatorChar,
                                    args[1] + File.separatorChar);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

class ProcessFwpAssertion implements CBORCryptoUtils.Collector {
    
    private FWPAssertionDecoder assertion;
    
    private static HashMap<CBORObject, PrivateKey> decryptionKeys;
    
    static void setDecryptionKeys(HashMap<CBORObject, PrivateKey> decryptionKeys) {
        ProcessFwpAssertion.decryptionKeys = decryptionKeys;
    }
    
    CBORDecrypter<?> decrypter = new CBORAsymKeyDecrypter(new CBORAsymKeyDecrypter.DecrypterImpl() {

            @Override
            public byte[] decrypt(PrivateKey privateKey,
                                  byte[] optionalEncryptedKey,
                                  PublicKey optionalEphemeralKey,
                                  KeyEncryptionAlgorithms keyEncryptionAlgorithm,
                                  ContentEncryptionAlgorithms contentEncryptionAlgorithm) {
                return EncryptionCore.decryptKey(true,
                                                 privateKey, optionalEncryptedKey,
                                                 optionalEphemeralKey,
                                                 keyEncryptionAlgorithm,
                                                 contentEncryptionAlgorithm);
            }

            @Override
            public PrivateKey locate(PublicKey optionalPublicKey,
                                     CBORObject keyId,
                                     KeyEncryptionAlgorithms keyEncryptionAlgorithm,
                                     ContentEncryptionAlgorithms contentEncryptionAlgorithm) {
                if (keyId == null) {
                    throw new CryptoException("Missing keyId");
                }
                PrivateKey privateKey = decryptionKeys.get(keyId);
                if (privateKey == null) {
                    throw new CryptoException("Private key not found: " + keyId);
                }
                return privateKey;
            }
            
        }).setTagPolicy(CBORCryptoUtils.POLICY.MANDATORY, new CBORCryptoUtils.Collector() {
            
            @Override
            public void foundData(CBORObject tag) {
                String typeUrl = tag.getTag().getTaggedObject().getArray().get(0).getString();
                if (!FWPCrypto.FWP_ESAD_OBJECT_ID.equals(typeUrl)) {
                    throw new CryptoException("Unexpected type URL: " + typeUrl);
                }
            }

        }).setCustomDataPolicy(CBORCryptoUtils.POLICY.MANDATORY, this); 
    
    CBORObject paymentRequest;
    
    ProcessFwpAssertion(byte[] encryptedAssertion) {
        CBORMap decryptedFwpAssertion = 
        CBORDecoder.decode(
                        decrypter.decrypt(CBORDecoder.decode(encryptedAssertion))).getMap();
        CBORMap pr = paymentRequest.getMap();
/*
        pr.remove(FWPPaymentRequest.CBOR_PR_PAYEE_NAME);
        pr.set(FWPPaymentRequest.CBOR_PR_PAYEE_NAME, new CBORString("fake"));
        paymentRequest = pr;
*/
        // Restore SAD
        decryptedFwpAssertion.set(FWPElements.PAYMENT_REQUEST.cborLabel, paymentRequest);
        
        assertion = new FWPAssertionDecoder(decryptedFwpAssertion);
        
    }

    @Override
    public void foundData(CBORObject customData) {
        // Custom data holds the payment request
        paymentRequest = customData;
    }
}
