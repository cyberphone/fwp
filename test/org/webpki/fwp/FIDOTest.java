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

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.File;
import java.io.IOException;

import java.net.URL;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

import java.util.GregorianCalendar;

import org.junit.BeforeClass;
import org.junit.Test;

import org.webpki.cbor.CBORObject;
import org.webpki.cbor.CBORPublicKey;

import org.webpki.crypto.CustomCryptoProvider;
import org.webpki.crypto.HashAlgorithms;

import org.webpki.jose.JOSEKeyWords;

import org.webpki.json.JSONArrayReader;
import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONObjectWriter;
import org.webpki.json.JSONOutputFormats;
import org.webpki.json.JSONParser;

import org.webpki.util.ArrayUtil;

/**
 * JSON JUnit suite
 */
public class FIDOTest {
    
    static JSONObjectReader testVectors;
    
    static FWPCrypto.FWPPreSigner fwpPreSigner;
    
    static String keyDir;
    String currPrivateKey;
    
    KeyPair readKey(String keyAlg) throws IOException {
        JSONObjectReader key = 
                JSONParser.parse(ArrayUtil.readFile(keyDir + keyAlg + "privatekey.jwk"));
        key.removeProperty(JOSEKeyWords.KID_JSON);
        currPrivateKey = key.toString();
        return key.getKeyPair();
    }
    

    @BeforeClass
    public static void openFile() throws Exception {
        // Start deprecating Bouncycastle since Android will remove most of it anyway
        CustomCryptoProvider.forcedLoad(false);
        testVectors = JSONParser.parse(ArrayUtil.readFile(System.getProperty("json.data")));
        keyDir = System.getProperty("sample.keys") + File.separatorChar;
    }
    
    void checkException(Exception e, String compareMessage) {
        String m = e.getMessage();
        String full = m;
        if (compareMessage.length() < m.length()) {
            m = m.substring(0, compareMessage.length());
        }
        if (!m.equals(compareMessage)) {
            fail("Exception: " + full + "\ncompare: " + compareMessage);
        }
    }

    byte[] clientDataJson(JSONObjectReader response,
                          String subType,
                          String rpUrl,
                          byte[] challenge) throws Exception {
        byte[] clientDataJSON = response.getBinary(FWPCrypto.CLIENT_DATA_JSON);
        JSONObjectReader json = JSONParser.parse(clientDataJSON);
        assertTrue(FWPCrypto.CDJ_TYPE, json.getString(FWPCrypto.CDJ_TYPE).equals(subType));
        assertTrue(FWPCrypto.CDJ_ORIGIN, json.getString(FWPCrypto.CDJ_ORIGIN).equals(rpUrl));
        assertTrue(FWPCrypto.CHALLENGE, ArrayUtil.compare(challenge, 
                                                          json.getBinary(FWPCrypto.CHALLENGE)));
        return clientDataJSON;
    }
    
    PublicKey getPublicKey(CBORObject attestation, 
                           String rpUrl,
                           byte[] credentialId) throws Exception {
// System.out.println(attestation.toString());
        byte[] authData = attestation.getMap().getObject("authData").getByteString();
// System.out.println(DebugFormatter.getHexDebugData(authData));
        byte[] rpId = HashAlgorithms.SHA256.digest(new URL(rpUrl).getHost().getBytes("utf-8"));
        assertTrue("rpId", ArrayUtil.compare(authData, rpId, 0, 32));
        return CBORPublicKey.decode(CBORObject.decode(
                FWPCrypto.extractFidoPublicKey(attestation.encode())));
    }
    
 
    void test(JSONObjectReader vector) throws Exception {
        String userAgent = vector.getString("userAgent");
        String token = vector.getString("token");
        String rpUrl = vector.getString("rpUrl");
        JSONObjectReader create = vector.getObject("create");
        byte[] createChallenge = create.getBinary(FWPCrypto.CHALLENGE);
        String userId = create.getString(FWPCrypto.USER_ID);
        JSONObjectReader createResponse = vector.getObject("create.response");
        byte[] createCredentialId = createResponse.getBinary(FWPCrypto.CREDENTIAL_ID);
        CBORObject attestation = 
                CBORObject.decode(createResponse.getBinary(FWPCrypto.ATTESTATION_OBJECT));
        PublicKey publicKey = getPublicKey(attestation, rpUrl, createCredentialId);
        byte[] createClientDataJSON = clientDataJson(createResponse, 
                                                     FWPCrypto.CDJ_CREATE_ARGUMENT, 
                                                     rpUrl, 
                                                     createChallenge);
        JSONObjectReader get = vector.getObject("get");
        byte[] getCredentialId = get.getBinary(FWPCrypto.CREDENTIAL_ID);
        assertTrue("keyHandle", ArrayUtil.compare(createCredentialId, getCredentialId));
        byte[] getChallenge = get.getBinary(FWPCrypto.CHALLENGE);
        JSONObjectReader getResponse = vector.getObject("get.response");
        byte[] authenticatorData = getResponse.getBinary(FWPCrypto.AUTHENTICATOR_DATA_JSON);
        byte[] signature = getResponse.getBinary(FWPCrypto.SIGNATURE_JSON);
        byte[] getClientDataJSON = clientDataJson(getResponse, 
                                                  FWPCrypto.CDJ_GET_ARGUMENT, 
                                                  rpUrl, 
                                                  getChallenge);
        FWPCrypto.validateFidoSignature(
                FWPCrypto.getWebPkiAlgorithm(
                        FWPCrypto.publicKey2CoseSignatureAlgorithm(publicKey)),
                publicKey,
                authenticatorData, 
                getClientDataJSON, 
                signature);
    }

    @Test
    public void CreateAndGet() throws Exception {
        JSONArrayReader vectors = testVectors.getJSONArrayReader();
        while (vectors.hasMore()) {
            test(vectors.getObject());
        }
        testVectors.checkForUnread();
    }
    
    String getPaymentRequest(boolean goodName, boolean allIsThere) throws IOException {
        return new JSONObjectWriter()
            .setString(FWPElements.JSON_PR_PAYEE, goodName ? "Space Shop" : "Evil Merchant")
            .setDynamic((wr)-> allIsThere ? wr.setString(FWPElements.JSON_PR_ID, "65656") : wr)
            .setString(FWPElements.JSON_PR_AMOUNT, "140.00")
            .setString(FWPElements.JSON_PR_CURRENCY, "EUR")
            .serializeToString(JSONOutputFormats.NORMALIZED);
    }
    
    byte[] buildGoodPaymenRequest(String networkData,
                                  PrivateKey privateKey) throws IOException,
                                                                GeneralSecurityException {
        return FWPCrypto.directSign(
                new FWPAssertionBuilder()
            .addPaymentRequest(getPaymentRequest(true, true))
            .addPayeeHostName("spaceshop.com")
            .addAccountData("FR7630002111110020050014382",
                            "057862932",
                            "https://bankdirect.com")
            .addPlatformData("Android", "10.0", "Chrome", "103")
            .addUserAuthorizationMethod(FWPElements.UserAuthorizationMethods.FINGERPRINT)
            .addOptionalNetworkData(networkData)
            .create(fwpPreSigner),
            privateKey, "https://mybank.com");
    }
    
    @Test
    public void CreateAssertions() throws Exception {
        try {
            new FWPAssertionBuilder()
                .addPaymentRequest(getPaymentRequest(true, false))
                .create(fwpPreSigner);
            fail("Must not execute");
        } catch (Exception e) {
            checkException(e, "Property \"id\" is missing");
        }

        try {
            new FWPAssertionBuilder()
                .addPaymentRequest(getPaymentRequest(true, true))
                .create(fwpPreSigner);
            fail("Must not execute");
        } catch (Exception e) {
            checkException(e, "Missing element: PAYEE_HOST_NAME");
        }

        try {
            new FWPAssertionBuilder()
                .addPaymentRequest(getPaymentRequest(true, true))
                .addPayeeHostName("example.com")
                .addPayeeHostName("example.com")
                .create(fwpPreSigner);
            fail("Must not execute");
        } catch (Exception e) {
            checkException(e, "Duplicate: PAYEE_HOST_NAME");
        }
        
    }
    
    @Test
    public void DecodeAssertions() throws Exception {
        KeyPair keyPair = readKey("p256");
        fwpPreSigner = new FWPCrypto.FWPPreSigner(keyPair.getPublic());
        FWPAssertionDecoder decoder = 
                new FWPAssertionDecoder(buildGoodPaymenRequest(null, keyPair.getPrivate()));
        FWPAssertionDecoder.PaymentRequest paymentRequest = decoder.getPaymentRequest();
        assertTrue("payee", paymentRequest.getPayee().equals("Space Shop"));
        assertTrue("id", paymentRequest.getId().equals("65656"));
        assertTrue("amount", paymentRequest.getAmount().equals("140.00"));
        assertTrue("currency", paymentRequest.getCurrency().equals("EUR"));
        assertTrue("host", decoder.getHostName().equals("spaceshop.com"));
        assertTrue("fp", decoder.getUserAuthorizationMethod().equals(
                FWPElements.UserAuthorizationMethods.FINGERPRINT));
        assertTrue("nd", decoder.getNetworkData() == null);
        assertTrue("account", decoder.getAccountId().equals("FR7630002111110020050014382"));
        assertTrue("sn", decoder.getSerialNumber().equals("057862932"));
        assertTrue("pm", decoder.getPaymentMethod().equals("https://bankdirect.com"));
        long now = new GregorianCalendar().getTimeInMillis();
        long then = decoder.getTimeStamp().getTimeInMillis();
        assertTrue("time", now >= then && now - then < 10000);
        decoder = new FWPAssertionDecoder(buildGoodPaymenRequest(
                "{\"service\":\"https://mybank.com/fwp\"}", keyPair.getPrivate()));
        assertTrue("nd", decoder.getNetworkData().toString()
                .equals("{\n  \"service\": \"https://mybank.com/fwp\"\n}"));
        decoder.verifyClaimedPaymentRequest(getPaymentRequest(true, true));
        try {
            decoder.verifyClaimedPaymentRequest(getPaymentRequest(false, true));
            fail("should not execute");
        } catch (Exception e) {
            assertTrue("claimed", e.getMessage().contains("Claimed"));
        }
    }
}
