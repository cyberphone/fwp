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

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.net.URL;
import java.security.PublicKey;

import org.junit.BeforeClass;
import org.junit.Test;

import org.webpki.cbor.CBORObject;
import org.webpki.cbor.CBORPublicKey;

import org.webpki.crypto.CustomCryptoProvider;
import org.webpki.crypto.HashAlgorithms;
import org.webpki.crypto.KeyAlgorithms;
import org.webpki.crypto.SignatureWrapper;
import org.webpki.json.JSONArrayReader;
import org.webpki.json.JSONObjectReader;
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
/*
 {
  "userAgent": "Chrome90/W10",
  "token": "Windows Hello",
  "create": {
    "challenge": "5UBX2l8hj-K0LHxy_J8kSHwtiDNE-j6N4yU2pMJbWRo",
    "userId": "6c64bd60-ae65-40ff-8a5a-58a3f7c188b2"
  },
  "create.response": {
    "keyHandle": "VQ4aRuTTG3O7lq_7hnYKfKArUuNzys4Hl_b4QmVCygQ",
    "attestation": "o2NmbXRjdHBtZ2F0dFN0bXSmY2FsZzn__mNzaWdZAQBaJlgKwig22fEhdhsY326ud9TC64lUvMcZHRDt4mncfi2fv00bAjegJPblxrQbVxo8jTPE08Tj3Ez2NdLbYGHTRrmbQRmGT-GWVJw9-7tkJrIg-DkrF4S4x6kXUAIXU9L7Ky-1SqrwfdnC21TSF6CJp2A5r_S6kZYH6zlBwmXrgcQ9lSYhYtsIRzDp6zA7le18g7y6qdYhCdgJhZkQ1VO5-43TSz8OQzYrxS5y96RxRSfuOFEWM0oswmfznUlULL6sSu7w2RrK8BKdCrwnpG1NooSRali9fbJ02pd7uj_soFkqJgU7-3wfkTCYUK3Po8-VygNzM4-OXyHI62ddDRZ8Y3ZlcmMyLjBjeDVjglkFxDCCBcAwggOooAMCAQICEGGxHpgqdE_OlqocAQLkEicwDQYJKoZIhvcNAQELBQAwQTE_MD0GA1UEAxM2TkNVLVNUTS1LRVlJRC1GQjE3RDcwRDczNDg3MEU5MTlDNEU4RTYwMzk3NUU2NjRFMEU0M0RFMB4XDTIxMDQwODE3NTMxNVoXDTI1MDYxODE5MTYzNlowADCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL5Pk9uNVX64lX3VqtfCCQVdhISbSdsh2ZncL4evq9T27arkSr8ataSe-sPMT592O63bWncE2GHzRTwusM37USQYR7aVONY6PWGRve-62MPdvNe3OB4KUZRX1JypkyOX8UCEjzHgoPjKAB6_9BpkhmWfPXRlJ-JZ1i_6uexoWpZSp4X3OGAZnC9YZVbx2dsQv9HCC-a2nGEBzeBJpn0sXSzZtig-slBtRnMp-nqPMLvG8L0P-hVXbF7Fc4oLTSV_QAEbKrKXd6Dj91tijlQLRjO4uGhGj7Hha4xg2H9ADi2Oi2Z1e7kn-amF_pYrtklRKKlX8QrfJMcaFeCgZ7UKohcCAwEAAaOCAfMwggHvMA4GA1UdDwEB_wQEAwIHgDAMBgNVHRMBAf8EAjAAMG0GA1UdIAEB_wRjMGEwXwYJKwYBBAGCNxUfMFIwUAYIKwYBBQUHAgIwRB5CAFQAQwBQAEEAIAAgAFQAcgB1AHMAdABlAGQAIAAgAFAAbABhAHQAZgBvAHIAbQAgACAASQBkAGUAbgB0AGkAdAB5MBAGA1UdJQQJMAcGBWeBBQgDMFkGA1UdEQEB_wRPME2kSzBJMRYwFAYFZ4EFAgEMC2lkOjUzNTQ0RDIwMRcwFQYFZ4EFAgIMDFNUMzNIVFBIQUhENDEWMBQGBWeBBQIDDAtpZDowMDAxMDEwMTAfBgNVHSMEGDAWgBRsY8IPY1tegaOhw5qmjmaoh5cEIjAdBgNVHQ4EFgQUJ0sg7ghDwjEfnZQyBgbpGiUQSf8wgbIGCCsGAQUFBwEBBIGlMIGiMIGfBggrBgEFBQcwAoaBkmh0dHA6Ly9hemNzcHJvZG5jdWFpa3B1Ymxpc2guYmxvYi5jb3JlLndpbmRvd3MubmV0L25jdS1zdG0ta2V5aWQtZmIxN2Q3MGQ3MzQ4NzBlOTE5YzRlOGU2MDM5NzVlNjY0ZTBlNDNkZS8xNTk2YWYyYy0yZGRiLTQ2ZDctYmUzYi01NDAwODU5YmYzMjAuY2VyMA0GCSqGSIb3DQEBCwUAA4ICAQCFk1eoL3hPKRDn5w7TCzngR3L2VVda8xL9SVH6Krk9Hg2tNSIo9LW9vGDHT96BjXu9-0jPXg_pxPXErLU83gsaHy_nt6B8Uvmq16NQPlLnNZ2bdQe1kbIcBJXZ2DsTFosIDwC3L0CDAxPoKhefn9B8BpVSGV7OhY3AUSc4ZGPWQ-dMEAAm_uKj0hCn9jGOsXy9lEShMm5_MNRHrsjMmzztNJYx5t27n5ZMEWdEJxw2NFNgje3XsYG6xtVSHaL-Mvf7XgOwxJdwc-vaei7-KWoijox8E5KHzpyI_vW5YajRdBGYrR9RM2vDW-7de9mdWwIyXsVkbZVj5dSVoEqf4DWpwODEbRrBdGUfGEYsXxkfjbgxFoEVh1WCUYw9vPdQnmkzQgPLqyS-oqBRJw1I0VIfrVj7tNRkSJHpeC8yhGJR2n_9j5MxQRxuttZcLY3oN5nTzQSc-AmMz8qHy88ZFH9kVUxw9N-JIRxr-bgVXDl9XRDrv1JJu3te4uOEqsNPJAtbKRwO4hkeSe4u0BVD9RnhoXdFR_7es2plI8bjEAWGuT4NYkXs0Pj7g608oK1NUEuU75h6i-MaDlQPyrbaeMPyxYBgvXRiH9AekhXMYpPp628sVpW_6v9DDYif9fUHzqyqaCcDbrA9J5NS_BkmOuI1uioaYuwhz_5R9qMLZtPj_VkG7zCCBuswggTToAMCAQICEzMAAALnYq6-Ce5vs0UAAAAAAucwDQYJKoZIhvcNAQELBQAwgYwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xNjA0BgNVBAMTLU1pY3Jvc29mdCBUUE0gUm9vdCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgMjAxNDAeFw0yMDA2MTgxOTE2MzZaFw0yNTA2MTgxOTE2MzZaMEExPzA9BgNVBAMTNk5DVS1TVE0tS0VZSUQtRkIxN0Q3MEQ3MzQ4NzBFOTE5QzRFOEU2MDM5NzVFNjY0RTBFNDNERTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAO6KcW8-0Y0AYoVk0B8y0qiCtTDeCzEvpSOUyhAcI15PkInqi-LkcGem_VzipVTwitth7JLHgrvn97-WQDNX2-I586LW25VIfl5lQ16I6SShtU6fnpaqcWrd8IDQRaPXgZFhi4ohbd2QvE9HfL8WAThx_IYLyEnEwW6nRt0Pb0gilUzEDAteAgXVakNe69hbjr6YR6zQZHxrxPUyPEXoXRU6j8szdRkiOvXnfQqjDtZjn6R76tZpCXovQlZzjgaG8AoMlYk9j_6Hc3WdGxPjK-5PrN8rXqhm9rJ1ELf0swg56FrxXrejgLY130_P4zRG3VGkXzL_sIffoVWtO3HkGdx6yMKQUrI9xu1Gapzo2uC7pYApybwwo1sJVaEM2qRKvKEsKfFybdtGyN1h5Hy9PlePIggiEsGZbr8vJTg045rW53qivNaBwnVS8Ojo6H0Su40yclafg7iFttKOyhvKn_OHKg3XDiROxxZtkZgjYv7plR4ZuFC2GIYSQ_4ZGFuXli1rkxAIhcCH_BwNx1J1y9ksT96fGGTnZ6O4bN7evejNkB-gZeqru-8xz4BjRX86-pzYoXMQrUFQYoUbH-WgBdkPbfoNX3-4Ax9HGY8GZeihM1XDowi5r1CObIoRIzs1oywg3gWxhVgyqDJEDpBEvIz3N9cJC_BdHdwZuEIusHADAgMBAAGjggGOMIIBijAOBgNVHQ8BAf8EBAMCAoQwGwYDVR0lBBQwEgYJKwYBBAGCNxUkBgVngQUIAzAWBgNVHSAEDzANMAsGCSsGAQQBgjcVHzASBgNVHRMBAf8ECDAGAQH_AgEAMB0GA1UdDgQWBBRsY8IPY1tegaOhw5qmjmaoh5cEIjAfBgNVHSMEGDAWgBR6jArOL0hiF-KU0a5VwVLscXSkVjBwBgNVHR8EaTBnMGWgY6Bhhl9odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NybC9NaWNyb3NvZnQlMjBUUE0lMjBSb290JTIwQ2VydGlmaWNhdGUlMjBBdXRob3JpdHklMjAyMDE0LmNybDB9BggrBgEFBQcBAQRxMG8wbQYIKwYBBQUHMAKGYWh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY2VydHMvTWljcm9zb2Z0JTIwVFBNJTIwUm9vdCUyMENlcnRpZmljYXRlJTIwQXV0aG9yaXR5JTIwMjAxNC5jcnQwDQYJKoZIhvcNAQELBQADggIBAEgzeDEFzkmd33cIyEWCxPyrDIwfU6p6XiKXlAikxU71B5x_6vQR-V2LajjF-F4W_zeqsGDjaQyvDeVBu2JCmqiBGdfEp83qP9kZyuLHadA7e1vGBcPMDTzI1BMKfL14HpZ2yRjT50O77C-kvOsSBKT8s2v7QXaxkdpZCwVDlDx03JGcFBmWt-X0zTWARSzEhLX4dzaR8kJervMiX_6MsIbpiO6_VSoMy6EGNc_Y-LM86VWQ3u3vAHp9ugNe6QODWE8z37Jtrzw8mHZaefx89Qie6J8Z91vYQCWsMXrNVEUdYpkF1vWznPPgprMTuniS_E_0zVm6Jk7usQ1Dsd3lwxyJLRQDT6nt4vIiZ8tRWp6eK9yjJQfFq--Ftre2zCaPb4ce3oDIHiBy-qBPoYQqkBjXnC0dQ6kVa6LKLkwNHKd4yz3nLUQNS6mnX3xExkuyliIQI-GL7RIaJ9FZMXhWEQofXjlNk5fEMPtgU-AxpyxqctllzgZKc8Dxc6togAm2mgQMDrRBknLk4VY8JVrHK8IcMGldpW2KL3llkBGVbfErEZ8sinNewrTtsuEE4x_bWRACZjZEM2Z5-aovejxgtBVVQANNVefKHHK31r3o1BssiGw-jKh-xvmhXqb47Vh2q2GgCStkS1Ya-U7pzNIfWdwuuLH1mNGrTbuHSFDYy8GkZ3B1YkFyZWFZATYAAQALAAYEcgAgnf_L82w4OuaZ-5ho3G3LidcVOIS-KAOSLBJBWL-tIq4AEAAQCAAAAAAAAQC4fEJX01JJRvw163gJHMoFDUAcisw_56Pa6AvtWuP49huZeVdbNNePeWzpdlwqg-r_vfIVksYqtCNYo307Fnocng4BYKJF0l8Lb-n0BrCB94ExvGVuNydbu4q-_CwopdyWMS_fWWuOCiDoPp-VxPND68edcQ_hcAGAgQzP1HcMPR1xNkpfzi60g66Z9X7pu1k5bu1Uv8Wvr0YK6fsk6zj0CY9EDMKNnmOmWM8BBzgsWd6QDIJJMTeELOSApx8_nt7P_gVCWWsAVCKK6pNkh0bFBU5Q_argf9e2Hd2ObwGpmp5uZ8pzHuBHGRJrVUT6RQfbJIH1mqf_GOA6q7lyJwVZaGNlcnRJbmZvWKH_VENHgBcAIgAL_poTIssY7b792oKBK0w0r6iomfaU8fVu2ugWwM9hiz0AFP8ut6Rv8l-5DSfMCTfGk06IDNgjAAAAAAY6foarxNdz-vienwGTs-9n6qV0CwAiAAvFu1rYT9cRmrizv6nbJYKFgGILkDoIYqmGIIR8_lNDUAAiAAv4gCHNHb5Tkuyaeiek6fAZ0q5Si0FFM9g3xQGGgIneGWhhdXRoRGF0YVkBZykqrV_lqNyaVkKbKwhk9pEk0R2WFrqDcuDE0hUze-W9RQAAAAAImHBYytxLgbbhMN5Q3L6WACBVDhpG5NMbc7uWr_uGdgp8oCtS43PKzgeX9vhCZULKBKQBAwM5AQAgWQEAuHxCV9NSSUb8Net4CRzKBQ1AHIrMP-ej2ugL7Vrj-PYbmXlXWzTXj3ls6XZcKoPq_73yFZLGKrQjWKN9OxZ6HJ4OAWCiRdJfC2_p9AawgfeBMbxlbjcnW7uKvvwsKKXcljEv31lrjgog6D6flcTzQ-vHnXEP4XABgIEMz9R3DD0dcTZKX84utIOumfV-6btZOW7tVL_Fr69GCun7JOs49AmPRAzCjZ5jpljPAQc4LFnekAyCSTE3hCzkgKcfP57ez_4FQllrAFQiiuqTZIdGxQVOUP2q4H_Xth3djm8BqZqebmfKcx7gRxkSa1VE-kUH2ySB9Zqn_xjgOqu5cicFWSFDAQAB",
    "clientData": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiNVVCWDJsOGhqLUswTEh4eV9KOGtTSHd0aURORS1qNk40eVUycE1KYldSbyIsIm9yaWdpbiI6Imh0dHBzOi8vbW9iaWxlcGtpLm9yZyIsImNyb3NzT3JpZ2luIjpmYWxzZX0"
  },
  "get": {
    "keyHandle": "VQ4aRuTTG3O7lq_7hnYKfKArUuNzys4Hl_b4QmVCygQ",
    "challenge": "WkFsNCD6mN6oYIblws9iM5srfm2iv_pkTqADiokv9mo"
  },
  "get.response": {
    "authenticatorData": "KSqtX-Wo3JpWQpsrCGT2kSTRHZYWuoNy4MTSFTN75b0FAAAAAQ",
    "signature": "Ai2UCswbdZiY5Yo5s326joLRFcaN2q6Lg82cIwmX3l0qik3IlLwjaulSEwdq31dhRCeVsg-_SffQ-Q0-JB43ggWIGfB5J6JR1-WfNslAaQSvnbMfIZ0haTmhcu1ZwXCHSkH9VDHCWTbfCInFTMCGl1vyMPt0aYIbkuz3gt6lArYnY808TxyUtVdbGdFwb4XUVRCWd_ycIfRAdTFPIBDp1GrKdzRF97inGkiQgx3Vym7PBFN3t-ZZ1dELK2MKfH_GP0TDS7x1RLtoDwKz5XE1ZCmU4zRsg7GG-vI3i8CWDhBGH4veoULYD0yiTmqQdgjZsUchsAJgoyGDCBvR3708ww",
    "clientData": "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiV2tGc05DRDZtTjZvWUlibHdzOWlNNXNyZm0yaXZfcGtUcUFEaW9rdjltbyIsIm9yaWdpbiI6Imh0dHBzOi8vbW9iaWxlcGtpLm9yZyIsImNyb3NzT3JpZ2luIjpmYWxzZX0"
  }
}
 */
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
    
    PublicKey getPublicKey(CBORObject attestation, String rpUrl, byte[] keyHandle) throws Exception {
// System.out.println(attestation.toString());
        byte[] authData = attestation.getTextStringMap().getMappedValue("authData").getByteString();
// System.out.println(DebugFormatter.getHexDebugData(authData));
        byte[] rpId = HashAlgorithms.SHA256.digest(new URL(rpUrl).getHost().getBytes("utf-8"));
        assertTrue("rpId", ArrayUtil.compare(authData, rpId, 0, 32));
        assertFalse("AT", (authData[32] & 0x40) == 0);
   
        int i = 32 + 1 + 4 + 16;
        int credentialIdLength = (authData[i++] << 8) + authData[i++];
        assertTrue("credentialIdLength", credentialIdLength == keyHandle.length);
        assertTrue("credentialId", ArrayUtil.compare(authData, i, keyHandle, 0, credentialIdLength));
        int offset = i + credentialIdLength;
        byte[] rawPublicKey = new byte[authData.length - offset];
        System.arraycopy(authData, offset, rawPublicKey, 0, rawPublicKey.length);
        return CBORPublicKey.decode(CBORObject.decode(rawPublicKey));
    }
    
 
    void test(JSONObjectReader vector) throws Exception {
        String userAgent = vector.getString("userAgent");
        String token = vector.getString("token");
        String rpUrl = vector.getString("rpUrl");
        JSONObjectReader create = vector.getObject("create");
        byte[] createChallenge = create.getBinary(FWPCommon.RP_CHALLENGE_JSON);
        String userId = create.getString(FWPCommon.RP_USER_ID);
        JSONObjectReader createResponse = vector.getObject("create.response");
        byte[] createKeyHandle = createResponse.getBinary(FWPCommon.KEY_HANDLE_JSON);
        CBORObject attestation = 
                CBORObject.decode(createResponse.getBinary(FWPCommon.ATTESTATION_JSON));
        PublicKey publicKey = getPublicKey(attestation, rpUrl, createKeyHandle);
        byte[] createClientData = clientDataJson(createResponse, "webauthn.create", rpUrl, createChallenge);
        JSONObjectReader get = vector.getObject("get");
        byte[] getKeyHandle = get.getBinary(FWPCommon.KEY_HANDLE_JSON);
        assertTrue("keyHandle", ArrayUtil.compare(createKeyHandle, getKeyHandle));
        byte[] getChallenge = get.getBinary(FWPCommon.RP_CHALLENGE_JSON);
        JSONObjectReader getResponse = vector.getObject("get.response");
        byte[] authenticatorData = getResponse.getBinary(FWPCommon.AUTHENTICATOR_DATA_JSON);
        byte[] signature = getResponse.getBinary(FWPCommon.SIGNATURE_JSON);
        byte[] getClientData = clientDataJson(getResponse, "webauthn.get", rpUrl, getChallenge);
        KeyAlgorithms keyAlgorithm = KeyAlgorithms.getKeyAlgorithm(publicKey);
        assertTrue("signature",
          new SignatureWrapper(keyAlgorithm.getRecommendedSignatureAlgorithm(), publicKey)
                .setEcdsaSignatureEncoding(true)
                .update(ArrayUtil.add(authenticatorData, HashAlgorithms.SHA256.digest(getClientData)))
                .verify(signature));

    }

    @Test
    public void CreateAndGet() throws Exception {
        JSONArrayReader vectors = testVectors.getJSONArrayReader();
        while (vectors.hasMore()) {
            test(vectors.getObject());
        }
        testVectors.checkForUnread();
    }
}
