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
package org.webpki.webapps.fwp;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.net.URL;
import java.security.PublicKey;

import org.junit.BeforeClass;
import org.junit.Test;

import org.webpki.cbor.CBORObject;
import org.webpki.cbor.CBORPublicKey;

import org.webpki.crypto.CustomCryptoProvider;
import org.webpki.crypto.HashAlgorithms;

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

    @BeforeClass
    public static void openFile() throws Exception {
        // Start deprecating Bouncycastle since Android will remove most of it anyway
        CustomCryptoProvider.forcedLoad(false);
        testVectors = JSONParser.parse(ArrayUtil.readFile(System.getProperty("json.data")));
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
        byte[] clientDataJSON = response.getBinary(FWPCommon.CLIENT_DATA_JSON);
        JSONObjectReader json = JSONParser.parse(clientDataJSON);
        assertTrue("type", json.getString("type").equals(subType));
        assertTrue("origin", json.getString("origin").equals(rpUrl));
        assertTrue("challenge", ArrayUtil.compare(challenge, json.getBinary("challenge")));
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
        byte[] createChallenge = create.getBinary(FWPCommon.CHALLENGE);
        String userId = create.getString(FWPCommon.USER_ID);
        JSONObjectReader createResponse = vector.getObject("create.response");
        byte[] createCredentialId = createResponse.getBinary(FWPCommon.CREDENTIAL_ID);
        CBORObject attestation = 
                CBORObject.decode(createResponse.getBinary(FWPCommon.ATTESTATION_OBJECT));
        PublicKey publicKey = getPublicKey(attestation, rpUrl, createCredentialId);
        byte[] createClientDataJSON = clientDataJson(createResponse, 
                                                     "webauthn.create", 
                                                     rpUrl, 
                                                     createChallenge);
        JSONObjectReader get = vector.getObject("get");
        byte[] getCredentialId = get.getBinary(FWPCommon.CREDENTIAL_ID);
        assertTrue("keyHandle", ArrayUtil.compare(createCredentialId, getCredentialId));
        byte[] getChallenge = get.getBinary(FWPCommon.CHALLENGE);
        JSONObjectReader getResponse = vector.getObject("get.response");
        byte[] authenticatorData = getResponse.getBinary(FWPCommon.AUTHENTICATOR_DATA_JSON);
        byte[] signature = getResponse.getBinary(FWPCommon.SIGNATURE_JSON);
        byte[] getClientDataJSON = clientDataJson(getResponse, 
                                                  "webauthn.get", 
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
    
    @Test
    public void CreateAssertions() throws Exception {
        try {
            new FWPAssertionBuilder()
                .addPaymentRequest(getPaymentRequest(true, false))
                .create();
            fail("Must not execute");
        } catch (Exception e) {
            checkException(e, "Property \"id\" is missing");
        }

        try {
            new FWPAssertionBuilder()
                .addPaymentRequest(getPaymentRequest(true, true))
                .create();
            fail("Must not execute");
        } catch (Exception e) {
            checkException(e, "Missing element: HOST_NAME");
        }

        try {
            new FWPAssertionBuilder()
                .addPaymentRequest(getPaymentRequest(true, true))
                .addHostName("example.com")
                .addHostName("example.com")
                .create();
            fail("Must not execute");
        } catch (Exception e) {
            checkException(e, "Duplicate: HOST_NAME");
        }
        
    }
    
    @Test
    public void DecodeAssertions() throws Exception {
        FWPAssertionDecoder decoder = new FWPAssertionDecoder(new FWPAssertionBuilder()
                .addPaymentRequest(getPaymentRequest(true, true))
                .addHostName("example.com")
                .create().encode());
        decoder.verifyClaimedPaymentRequest(getPaymentRequest(true, true));
        try {
            decoder.verifyClaimedPaymentRequest(getPaymentRequest(false, true));
            fail("should not execute");
        } catch (Exception e) {
            assertTrue("claimed", e.getMessage().contains("Claimed"));
        }
    }
}
