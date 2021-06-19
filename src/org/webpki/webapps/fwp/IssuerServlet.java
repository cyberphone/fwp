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
package org.webpki.webapps.fwp;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.logging.Logger;

import javax.servlet.ServletException;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.webpki.cbor.CBORAsymKeyDecrypter;
import org.webpki.crypto.encryption.KeyEncryptionAlgorithms;
import org.webpki.fwp.FWPAssertionDecoder;
import org.webpki.fwp.FWPJsonAssertion;
import org.webpki.fwp.FWPPaymentRequest;
import org.webpki.fwp.IssuerRequest;
import org.webpki.fwp.PSPRequest;
import org.webpki.json.JSONParser;

/**
 * TBD
 *
 */
public class IssuerServlet extends HttpServlet {
    
    static Logger logger = Logger.getLogger(IssuerServlet.class.getName());

    private static final long serialVersionUID = 1L;
    
    public static final String ISSUER_REQUEST = "issuerRequest";
    
    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {
        request.setCharacterEncoding("utf-8");
        try {
            String issuerRequest = request.getParameter(ISSUER_REQUEST);
            if (issuerRequest == null) {
                FWPWalletCore.failed("Missing Issuer request");
                return;
            }
            // Now the real work begins...
            IssuerRequest decodedIssuerRequest = new IssuerRequest(JSONParser.parse(issuerRequest));
            PSPRequest pspRequest = decodedIssuerRequest.getPspRequest();
            FWPJsonAssertion fwpJsonAssertion = pspRequest.getFwpAssertion();
            FWPPaymentRequest fwpPaymentRequest = pspRequest.getPaymentRequest();
            String payeeHost = decodedIssuerRequest.getPayeeHost();
            
            // Decrypt assertion.
            byte[] fwpAssertionBinary = new CBORAsymKeyDecrypter(new CBORAsymKeyDecrypter.KeyLocator() {

                @Override
                public PrivateKey locate(PublicKey publicKey,
                                         String keyId,
                                         KeyEncryptionAlgorithms algorithm)
                        throws IOException, GeneralSecurityException {
                    if (!FWPService.issuerKeyId.equals(keyId)) {
                        throw new GeneralSecurityException("Unknown keyId: " + keyId);
                    }
                    return FWPService.issuerEncryptionKey.getPrivate();
                }
                
            }).decrypt(fwpJsonAssertion.getEncryptedAuthorization());
            // Succeeded.
            
            // Decode assertion.
            FWPAssertionDecoder fwpAssertion = new FWPAssertionDecoder(fwpAssertionBinary);
            // Succeeded = the data is "technically" OK, and the signature verified.
            
            // Check merchant claim.
            fwpAssertion.verifyClaimedPaymentRequest(fwpPaymentRequest);
            // Succeeded.
            
            StringBuilder html = new StringBuilder(
    
                "<div class='header'>Received by the Issuer</div>" +
    
                "<div style='display:flex;justify-content:center;margin-top:15pt'>" +
                  "<div class='comment'>" +
                  "This part is still to be written..." +
                  "<div style='margin-top:0.4em'>Thanx for testing anyway!</div>" +
                  "</div>" +
                "</div>" +
                  
                "<div class='staticbox'>")
            .append(HTML.encode(decodedIssuerRequest.toString(), true))
            .append(
                "</div>");
            
            HTML.standardPage(response, FWPWalletCore.GO_HOME_JAVASCRIPT, html);
        } catch (Exception e) {
            HTML.errorPage(response, e);
        }
    }
}
