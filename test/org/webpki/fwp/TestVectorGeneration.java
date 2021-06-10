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

import org.webpki.cbor.CBORAsymKeyDecrypter;
import org.webpki.cbor.CBORAsymKeyEncrypter;
import org.webpki.cbor.CBORMap;
import org.webpki.cbor.CBORObject;

import org.webpki.crypto.CustomCryptoProvider;
import org.webpki.crypto.encryption.ContentEncryptionAlgorithms;
import org.webpki.crypto.encryption.KeyEncryptionAlgorithms;

import org.webpki.jose.JOSEKeyWords;
import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONObjectWriter;
import org.webpki.json.JSONOutputFormats;
import org.webpki.json.JSONParser;

import org.webpki.util.ArrayUtil;
import org.webpki.util.ISODateTime;

/**
 * Create FWP test vectors.
 */
public class TestVectorGeneration {
    

    static final Base64.Encoder Base64UrlEncoder = Base64.getUrlEncoder().withoutPadding();
    
    static final String ISSUER_URL = "https://fwp.mybank.com";
    static final String ISSUER_KEY_ID = "x25519:2021:3";
    static final KeyEncryptionAlgorithms ISSUER_KEY_ENCRYPTION_ALGORITHM =
            KeyEncryptionAlgorithms.ECDH_ES_A256KW;
    static final ContentEncryptionAlgorithms ISSUER_CONTENT_ENCRYPTION_ALGORITHM =
            ContentEncryptionAlgorithms.A256GCM;


    static final String MERCHANT_HOST = "spaceshop.com";
    
    static final String FILE_TESTVECTOR_TEXT = "vectors.txt";
    
    static final String FILE_UNSIGNED_CBOR   = "unsigned.cbor";
    static final String FILE_SIGNED_CBOR     = "signed.cbor";
    static final String FILE_ENCRYPTED_CBOR  = "encrypted.cbor";

    String testDataDir;
    String keyDir;
    
    String currPrivateKey;
    
    boolean signRewrite;
    
    StringBuilder result = new StringBuilder("FWP Test Vectors\n\n");
    
    KeyPair readKey(String keyAlg) throws IOException {
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
        
        FWPCrypto.FWPPreSigner fwpSigner = new FWPCrypto.FWPPreSigner(p256.getPublic());
       
        JSONObjectWriter paymentRequest = new JSONObjectWriter()
                .setString(FWPElements.JSON_PR_PAYEE, "Space Shop")
                .setString(FWPElements.JSON_PR_ID, "012345678")
                .setString(FWPElements.JSON_PR_AMOUNT, "140.50")
                .setString(FWPElements.JSON_PR_CURRENCY, "EUR");
        result.append("\n\nMerchant 'W3C PaymentRequest' data:\n")
              .append(paymentRequest.toString())
              .append("\nMerchant 'hostname' according to the browser: " + MERCHANT_HOST);
        String paymentRequestJson = paymentRequest.serializeToString(JSONOutputFormats.NORMALIZED);
        
        byte[] fwpAssertion = new FWPAssertionBuilder()
                .addPaymentRequest(paymentRequestJson)
                .addOptionalTimeStamp(ISODateTime.parseDateTime("2021-06-10T08:34:21+02:00",
                                                                ISODateTime.LOCAL_NO_SUBSECONDS))
                .addAccountData("FR7630002111110020050014382",
                                "0057162932",
                                "https://bankdirect.com")
                .addPlatformData("Android", "10.0", "Chrome", "103")
                .addUserAuthorizationMethod(FWPElements.UserAuthorizationMethods.FINGERPRINT)
                .addPayeeHostName(MERCHANT_HOST)
                .create(fwpSigner);
        
        result.append("\n\nThe FWP assertion (binary) converted into a SHA256 hash, here in Base64Url notation:\n")
              .append(Base64UrlEncoder.encodeToString(new byte[0]/*fwpSigner.getChallenge()*/))
              .append("\nThis is subsequently used as FIDO 'challenge'.");

        JSONObjectReader clientDataJSON = JSONParser.parse(new byte[0]/*fwpSigner.getClientDataJSON()*/);

        result.append("\n\nFIDO 'ClientDataJSON', here shown in clear:\n")
              .append(clientDataJSON.serializeToString(JSONOutputFormats.NORMALIZED));
        
        result.append("Relying party URL: " + ISSUER_URL + "\n" +
                      "\nFIDO Authenticator Data in Base64Url notation:\n")
              .append(Base64UrlEncoder.encodeToString(new byte[0]/*fwpSigner.getAuthenticatorData()*/))
              .append("\n(here using the UP flag and a zero counter value)\n");

        fwpAssertion = optionalSignatureRewrite(testDataDir + FILE_SIGNED_CBOR,
                                                fwpAssertion);

        result.append("\n\nSigned FWP assertion, here in CBOR 'diagnostic notation':\n")
              .append(CBORObject.decode(fwpAssertion).toString());
  
        byte[] unsignedFwpAssertion = CBORObject.decode(fwpAssertion)
                  .getMap().removeObject(FWPElements.AUTHORIZATION.cborLabel).encode();
            
        result.append("\n\n\nUnsigned FWP assertion, here in CBOR 'diagnostic notation':\n")
              .append(CBORObject.decode(unsignedFwpAssertion).toString());
            
        conditionalRewrite(testDataDir + FILE_UNSIGNED_CBOR, unsignedFwpAssertion);
        
        KeyPair x25519 = readKey("x25519");
        result.append("\n\nIssuer encryption key in JWK format:\n")
              .append(currPrivateKey);

        byte[] encryptedAssertion = 
                new CBORAsymKeyEncrypter(x25519.getPublic(),
                                         ISSUER_KEY_ENCRYPTION_ALGORITHM,
                                         ISSUER_CONTENT_ENCRYPTION_ALGORITHM)
                .setKeyId(ISSUER_KEY_ID).encrypt(fwpAssertion).encode();
        if (signRewrite) {
            ArrayUtil.writeFile(testDataDir + FILE_ENCRYPTED_CBOR, encryptedAssertion);
        } else {
            try {
                encryptedAssertion = ArrayUtil.readFile(testDataDir + FILE_ENCRYPTED_CBOR);
            } catch (Exception e) {
                
            }
        }
        
        result.append("\n\n\nEncrypted FWP assertion, here in CBOR 'diagnostic notation:\n")
              .append(CBORObject.decode(encryptedAssertion).toString());
        
        byte[] decryptedFwpAssertion = new CBORAsymKeyDecrypter(new CBORAsymKeyDecrypter.KeyLocator() {
            
            @Override
            public PrivateKey locate(PublicKey optionalPublicKey,
                                     String optionalKeyId,
                                     KeyEncryptionAlgorithms keyEncryptionAlgorithm)
                    throws IOException, GeneralSecurityException {
                if (!ISSUER_KEY_ID.equals(optionalKeyId)) {
                    throw new GeneralSecurityException("Wrong/missing ID");
                }
                return x25519.getPrivate();
            }
        }).decrypt(encryptedAssertion);
 
        FWPAssertionDecoder decodedFwpAssertion = new FWPAssertionDecoder(decryptedFwpAssertion);
        decodedFwpAssertion.verifyClaimedPaymentRequest(paymentRequestJson);
     //   decodedFwpAssertion.getPaymentRequest();
        
        conditionalRewrite(testDataDir + FILE_TESTVECTOR_TEXT, result.toString().getBytes("utf-8"));
    }

    void conditionalRewrite(String fileName, byte[] newFile) throws IOException {
        try {
            byte[] oldFile = ArrayUtil.readFile(fileName);
            if (ArrayUtil.compare(oldFile, newFile)) {
                return;
            }
        } catch (Exception e) {
            
        }
        ArrayUtil.writeFile(fileName, newFile);
    }


    CBORMap cleanSignature(byte[] assertion) throws IOException {
        CBORMap fwpAssertion = CBORObject.decode(assertion).getMap();
        fwpAssertion.getObject(FWPElements.AUTHORIZATION.cborLabel)
        .getMap().removeObject(FWPCrypto.AS_SIGNATURE);
        return fwpAssertion;
    }
    
    private byte[] optionalSignatureRewrite(String fileName, byte[] fwpAssertion) throws IOException {
        try {
            byte[] oldFwpAssertion = ArrayUtil.readFile(fileName);
            if (cleanSignature(oldFwpAssertion).equals(cleanSignature(fwpAssertion))) {
                return oldFwpAssertion;
            }
        } catch (IOException e) {
            
        }
        signRewrite = true;
        ArrayUtil.writeFile(testDataDir + FILE_SIGNED_CBOR, fwpAssertion);
        return fwpAssertion;
    }


    public static void main(String[] args) {
        try {
            CustomCryptoProvider.forcedLoad(false);
           new TestVectorGeneration(args[0] + File.separatorChar, args[1] + File.separatorChar);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
