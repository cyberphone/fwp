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

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;

import java.net.URL;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

import java.util.Arrays;
import java.util.GregorianCalendar;

import org.junit.BeforeClass;
import org.junit.Test;

import org.webpki.cbor.CBORBytes;
import org.webpki.cbor.CBORInt;
import org.webpki.cbor.CBORMap;
import org.webpki.cbor.CBORObject;
import org.webpki.cbor.CBORPublicKey;
import org.webpki.cbor.CBORString;

import org.webpki.crypto.CustomCryptoProvider;
import org.webpki.crypto.HashAlgorithms;

import org.webpki.jose.JOSEKeyWords;

import org.webpki.json.JSONArrayReader;
import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONParser;

import org.webpki.util.IO;
import org.webpki.util.UTF8;

/**
 * JSON JUnit suite
 */
public class FIDOTest {
    
    static JSONObjectReader testVectors;
    
    static FWPCrypto.FWPPreSigner fwpPreSigner;
    
    static String keyDir;
    String currPrivateKey;
    
    KeyPair readKey(String keyAlg) throws IOException, GeneralSecurityException {
        JSONObjectReader key = 
                JSONParser.parse(IO.readFile(keyDir + keyAlg + "privatekey.jwk"));
        key.removeProperty(JOSEKeyWords.KID_JSON);
        currPrivateKey = key.toString();
        return key.getKeyPair();
    }
    

    @BeforeClass
    public static void openFile() throws Exception {
        // Start deprecating Bouncycastle since Android will remove most of it anyway
        CustomCryptoProvider.forcedLoad(false);
        testVectors = JSONParser.parse(IO.readFile(System.getProperty("json.data")));
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
        assertTrue(FWPCrypto.CHALLENGE, Arrays.equals(challenge, 
                                                      json.getBinary(FWPCrypto.CHALLENGE)));
        return clientDataJSON;
    }
    
    PublicKey getPublicKey(CBORObject attestation, 
                           String rpUrl,
                           byte[] credentialId) throws Exception {
// System.out.println(attestation.toString());
        byte[] authData = attestation.getMap().get(FWPCrypto.AUTH_DATA_CBOR).getBytes();
// System.out.println(HexaDecimal.encode(authData));
        byte[] rpId = HashAlgorithms.SHA256.digest(UTF8.encode(new URL(rpUrl).getHost()));
        assertTrue("rpId", Arrays.equals(
                authData, 0, FWPCrypto.FLAG_OFFSET,  rpId, 0, FWPCrypto.FLAG_OFFSET));
        int credentialIdLength = (authData[FWPCrypto.CREDENTIAL_ID_LENGTH_OFFSET] << 8) + 
                                 (authData[FWPCrypto.CREDENTIAL_ID_LENGTH_OFFSET + 1] & 0xff);
        assertTrue("cil", credentialIdLength == credentialId.length);
        assertTrue("ci", Arrays.equals(authData,
                FWPCrypto.CREDENTIAL_ID_LENGTH_OFFSET + 2,
                FWPCrypto.CREDENTIAL_ID_LENGTH_OFFSET + 2 + credentialIdLength,
                credentialId,
                0,
                credentialIdLength));
        return CBORPublicKey.convert(CBORObject.decode(
                FWPCrypto.extractUserCredential(attestation.encode()).rawCosePublicKey));
    }
    
 
    void test(JSONObjectReader vector) throws Exception {
       // String userAgent = vector.getString("userAgent");
        String authenticator = vector.getString("authenticator");
        String rpUrl = vector.getString("rpUrl");
        JSONObjectReader create = vector.getObject("create");
        byte[] createChallenge = create.getBinary(FWPCrypto.CHALLENGE);
        JSONObjectReader createResponse = vector.getObject("create.response");
        byte[] createCredentialId = createResponse.getBinary(FWPCrypto.CREDENTIAL_ID);
        CBORObject attestation = 
                CBORObject.decode(createResponse.getBinary(FWPCrypto.ATTESTATION_OBJECT));
        PublicKey publicKey = getPublicKey(attestation, rpUrl, createCredentialId);
        assertTrue("alg=" + authenticator, createResponse.getInt("keyAlgorithm") ==
                FWPCrypto.publicKey2CoseSignatureAlgorithm(publicKey));
        assertTrue("pk=" + authenticator, createResponse.getPublicKey().equals(publicKey));
        byte[] createClientDataJSON = clientDataJson(createResponse,
                                                     FWPCrypto.CDJ_CREATE_ARGUMENT, 
                                                     rpUrl, 
                                                     createChallenge);
        JSONObjectReader get = vector.getObject("get");
        byte[] getCredentialId = get.getBinary(FWPCrypto.CREDENTIAL_ID);
        assertTrue("keyHandle", Arrays.equals(createCredentialId, getCredentialId));
        byte[] getChallenge = get.getBinary(FWPCrypto.CHALLENGE);
        JSONObjectReader getResponse = vector.getObject("get.response");
        byte[] authenticatorData = getResponse.getBinary(FWPCrypto.AUTHENTICATOR_DATA);
        byte[] signature = getResponse.getBinary(FWPCrypto.SIGNATURE);
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
    
    FWPPaymentRequest getPaymentRequest(boolean goodName) throws IOException {
        return new FWPPaymentRequest(goodName ? "Space Shop" : "Evil Merchant",
                                     "65656",
                                     "140.00",
                                     "EUR");
    }
    
    byte[] buildGoodPaymenRequest(String networkOptions,
                                  PrivateKey privateKey) throws IOException,
                                                                GeneralSecurityException {
        return FWPCrypto.directSign(new FWPAssertionBuilder()
                                        .setPaymentRequest(getPaymentRequest(true))
                                        .setPayeeHost("spaceshop.com")
                                        .setPaymentInstrumentData("FR7630002111110020050014382",
                                                                  "057862932",
                                                                  "https://banknet2.org")
                                        .setPlatformData("Android", "10.0", "Chrome", "103")
                                        .setNetworkOptions(networkOptions)
                                        .create(fwpPreSigner),
                                    privateKey, 
                                    "https://mybank.com",
                                    FWPCrypto.FLAG_UP + FWPCrypto.FLAG_UV,
                                    false);
    }
    
    @Test
    public void CreateAssertions() throws Exception {
        KeyPair keyPair = readKey("p256");
        fwpPreSigner = new FWPCrypto.FWPPreSigner(
             CBORPublicKey.convert(keyPair.getPublic()).encode());
        try {
            new FWPAssertionBuilder()
                .setPaymentRequest(getPaymentRequest(true))
                .create(fwpPreSigner);
            fail("Must not execute");
        } catch (Exception e) {
            checkException(e, "Missing element: PAYEE_HOST");
        }

        try {
            new FWPAssertionBuilder()
                .setPaymentRequest(getPaymentRequest(true))
                .setPayeeHost("example.com")
                .setPayeeHost("example.com")
                .create(fwpPreSigner);
            fail("Must not execute");
        } catch (Exception e) {
            checkException(e, "Duplicate: PAYEE_HOST");
        }
        
    }
    
    @Test
    public void DecodeAssertions() throws Exception {
        KeyPair keyPair = readKey("p256");
        fwpPreSigner = new FWPCrypto.FWPPreSigner(
             CBORPublicKey.convert(keyPair.getPublic()).encode());
        FWPAssertionDecoder decoder = 
                new FWPAssertionDecoder(buildGoodPaymenRequest(null, keyPair.getPrivate()));
        FWPPaymentRequest paymentRequest = decoder.getPaymentRequest();
        assertTrue("payee", paymentRequest.getPayeeName().equals("Space Shop"));
        assertTrue("id", paymentRequest.getRequestId().equals("65656"));
        assertTrue("amount", paymentRequest.getAmount().equals("140.00"));
        assertTrue("currency", paymentRequest.getCurrency().equals("EUR"));
        assertTrue("host", decoder.getPayeeHost().equals("spaceshop.com"));
        assertTrue("up", decoder.getUserValidation().contains(FWPCrypto.UserValidation.PRESENT));
        assertTrue("uv", decoder.getUserValidation().contains(FWPCrypto.UserValidation.VERIFIED));
        assertTrue("nd", decoder.getnetworkOptions() == null);
        assertTrue("account", decoder.getAccountId().equals("FR7630002111110020050014382"));
        assertTrue("sn", decoder.getSerialNumber().equals("057862932"));
        assertTrue("pm", decoder.getPaymentNetwork().equals("https://banknet2.org"));
        assertTrue("os", decoder.getOperatingSystem().getName().equals("Android"));
        assertTrue("ua", decoder.getUserAgent().getVersion().equals("103"));
        long now = new GregorianCalendar().getTimeInMillis();
        long then = decoder.getTimeStamp().getTimeInMillis();
        assertTrue("time", now >= then && now - then < 10000);
        decoder = new FWPAssertionDecoder(buildGoodPaymenRequest(
                "{\"service\":\"https://mybank.com/fwp\"}", keyPair.getPrivate()));
        assertTrue("nd", decoder.getnetworkOptions().toString()
                .equals("{\n  \"service\": \"https://mybank.com/fwp\"\n}"));
        decoder.verifyClaimedPaymentRequest(getPaymentRequest(true));
        try {
            decoder.verifyClaimedPaymentRequest(getPaymentRequest(false));
            fail("should not execute");
        } catch (Exception e) {
            assertTrue("claimed", e.getMessage().contains("Claimed"));
        }
    }
    
    void doOneAttestation(boolean hugeCi, boolean extension) throws Exception {
        String rpUrl = "https://example.com/g"; 
        KeyPair keyPair = readKey("p256");
        byte[] credentialId = UTF8.encode(hugeCi ? 
                "0123456701234567012345670123456701234567012345670123456701234567" +
                "0123456701234567012345670123456701234567012345670123456701234567" +
                "0123456701234567012345670123456701234567012345670123456701234567" +
                "HashAlgorithms.SHA256.digest(new URL(rpUrl).getHost().getBy     " +
                "0123456701234567012345670123456701234567012345670123456701234567" +
                "0123456701234567012345670123456701234567012345670123456701234567" 
                                                 :
                "012345670123456701234567012ByteArrayOutputStream");
        
        // authData object.
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] rpId = HashAlgorithms.SHA256.digest(UTF8.encode(new URL(rpUrl).getHost()));
        baos.write(rpId);
        baos.write(FWPCrypto.FLAG_AT);
        baos.write(new byte[] {0,5,2,70});
        baos.write(new byte[] {0,1,2,3,4,5,6,7,7,6,5,4,3,2,1,0});
        baos.write(credentialId.length >> 8);
        baos.write(credentialId.length & 0xff);
        baos.write(credentialId);
        
        CBORMap publicKey = CBORPublicKey.convert(keyPair.getPublic());
        publicKey.set(FWPCrypto.COSE_ALGORITHM_LABEL,
                      new CBORInt(FWPCrypto.publicKey2CoseSignatureAlgorithm(keyPair.getPublic())));
        baos.write(publicKey.encode());
        if (extension) {
            baos.write(new CBORMap().set(new CBORString("blah"), 
                                         new CBORInt(-3)).encode());
        }
        
        byte[] attestationObject = new CBORMap()
                .set(FWPCrypto.AUTH_DATA_CBOR, new CBORBytes(baos.toByteArray())).encode();
        assertTrue("pubk", keyPair.getPublic().equals(
                CBORPublicKey.convert(CBORObject.decode(FWPCrypto.extractUserCredential(attestationObject)
                        .rawCosePublicKey))));
    }
    
    @Test
    public void Attestations() throws Exception {
        doOneAttestation(false, false);
        doOneAttestation(false, true);
        doOneAttestation(true, false);
    }
}
