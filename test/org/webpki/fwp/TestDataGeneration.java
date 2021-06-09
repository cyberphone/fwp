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
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.KeyPair;

import java.util.Base64;

import org.webpki.cbor.CBOREncrypter;
import org.webpki.cbor.CBORInteger;
import org.webpki.cbor.CBORMap;
import org.webpki.cbor.CBORObject;
import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.crypto.CustomCryptoProvider;
import org.webpki.crypto.HashAlgorithms;

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
public class TestDataGeneration {
	

	static final Base64.Encoder Base64UrlEncoder = Base64.getUrlEncoder().withoutPadding();
	
	static final String RELYING_PARTY_URL = "https://fwp.mybank.com";

	static final String MERCHANT_HOST = "spaceshop.com";

    String testDataDir;
    String keyDir;
    
    String currPrivateKey;
    
    StringBuilder result = new StringBuilder("FWP Test Vectors\n\n");
    
    KeyPair readKey(String keyAlg) throws IOException {
    	JSONObjectReader key = 
    			JSONParser.parse(ArrayUtil.readFile(keyDir + keyAlg + "privatekey.jwk"));
    	key.removeProperty(JOSEKeyWords.KID_JSON);
    	currPrivateKey = key.toString();
    	return key.getKeyPair();
    }
    

    TestDataGeneration(String testDataDir, String keyDir) throws IOException,
                                                                 GeneralSecurityException {
        this.testDataDir = testDataDir;
        this.keyDir = keyDir;
            
        KeyPair p256 = readKey("p256");
        result.append("\n\nUser FIDO key in JWK format:\n")
              .append(currPrivateKey);
        
        FWPCrypto.FWPSigner fwpSigner = new FWPCrypto.FWPSigner(p256.getPrivate(),
                                                                p256.getPublic(),
                                                                RELYING_PARTY_URL);
       
        JSONObjectWriter paymentRequest = new JSONObjectWriter()
          		.setString(FWPElements.JSON_PR_PAYEE, "Space Shop")
          		.setString(FWPElements.JSON_PR_ID, "012345678")
          		.setString(FWPElements.JSON_PR_AMOUNT, "140.00")
          		.setString(FWPElements.JSON_PR_CURRENCY, "EUR");
        result.append("\n\nMerchant 'W3C PaymentRequest' data:\n")
              .append(paymentRequest.toString())
              .append("\nMerchant 'hostname' according to the browser: " + MERCHANT_HOST);
        String paymentRequestJson = paymentRequest.serializeToString(JSONOutputFormats.NORMALIZED);
        
        CBORMap fwpAssertion = new FWPAssertionBuilder()
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
        
        result.append("Relying party URL: " + RELYING_PARTY_URL + "\n" +
                      "\nFIDO Authenticator Data in Base64Url notation:\n")
              .append(Base64UrlEncoder.encodeToString(fwpSigner.getAuthenticatorData()))
              .append("\n(here using the UP flag and a zero counter value)\n");

	    KeyPair x25519 = readKey("x25519");
	    result.append("\n\nIssuer encryption key in JWK format:\n")
	          .append(currPrivateKey);

 

         result.append("\n\n\nUnsigned FWP assertion, here in CBOR 'diagnostic notation':\n")
              .append(CBORObject.decode(fwpAssertion.encode())
            		  .getMap().removeObject(FWPElements.AUTHORIZATION.cborLabel).toString());
        
        
        result.append("\n\nThe FWP assertion (binary) converted into a SHA256 hash, here in Base64Url notation:\n")
              .append(Base64UrlEncoder.encodeToString(fwpSigner.getChallenge()))
              .append("\nThis is subsequently used as FIDO 'challenge'.");

        JSONObjectReader clientDataJSON = JSONParser.parse(fwpSigner.getClientDataJSON());

        result.append("\n\nFIDO 'ClientDataJSON', here shown in clear:\n")
              .append(clientDataJSON.serializeToString(JSONOutputFormats.NORMALIZED));
         
        result.append("\n\nThe complete FWP assertion:\n")
              .append(fwpAssertion.toString());
        
        new FWPAssertionDecoder(fwpAssertion.encode());
        
        ArrayUtil.writeFile(testDataDir + "vectors.txt", result.toString().getBytes("utf-8"));
    }

    public static void main(String[] args) {
        try {
            CustomCryptoProvider.forcedLoad(false);
           new TestDataGeneration(args[0] + File.separatorChar, args[1] + File.separatorChar);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
