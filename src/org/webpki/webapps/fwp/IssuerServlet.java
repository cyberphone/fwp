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

import java.sql.Connection;

import java.util.GregorianCalendar;

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

import org.webpki.util.ISODateTime;

/**
 * The "finale", the receival by the Issuer.
 *
 */
public class IssuerServlet extends HttpServlet {
    
    static Logger logger = Logger.getLogger(IssuerServlet.class.getName());

    private static final long serialVersionUID = 1L;
    
    public static final String ISSUER_REQUEST = "issuerRequest";
    
    static long transactionId = 56807446412l;
    
    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {
        request.setCharacterEncoding("utf-8");
        try {
            String issuerRequest = request.getParameter(ISSUER_REQUEST);
            if (issuerRequest == null) {
                WalletCore.failed("Missing Issuer request");
                return;
            }
            // Now the real work begins...
            IssuerRequest decodedIssuerRequest = 
                    new IssuerRequest(JSONParser.parse(issuerRequest));
            PSPRequest pspRequest = decodedIssuerRequest.getPspRequest();
            FWPJsonAssertion fwpJsonAssertion = pspRequest.getFwpAssertion();
            FWPPaymentRequest fwpPaymentRequest = pspRequest.getPaymentRequest();
             
            // Decrypt assertion.
            byte[] fwpAssertionBinary = 
                    new CBORAsymKeyDecrypter(new CBORAsymKeyDecrypter.KeyLocator() {

                @Override
                public PrivateKey locate(PublicKey publicKey,
                                         String keyId,
                                         KeyEncryptionAlgorithms algorithm)
                        throws IOException, GeneralSecurityException {

                    // Somewhat simplistic setup: a single encryption key
                    if (!WalletService.issuerKeyId.equals(keyId)) {
                        throw new GeneralSecurityException("Unknown keyId: " + keyId);
                    }
                    return WalletService.issuerEncryptionKey.getPrivate();
                }
                
            }).decrypt(fwpJsonAssertion.getEncryptedAuthorization());
            // Succeeded.
            
            // Decode assertion.
            FWPAssertionDecoder fwpAssertion = 
                    new FWPAssertionDecoder(fwpAssertionBinary);
            // Succeeded = the data is "technically" OK, and the signature verified.
            
            // Check merchant claim.
            fwpAssertion.verifyClaimedPaymentRequest(fwpPaymentRequest);

            // Check that the user haven't been phished.
            compare(decodedIssuerRequest.getPayeeHost(), fwpAssertion.getPayeeHost());
            
            // And of course, verify that this assertion belongs to a valid account!
            String userId;
            try (Connection connection = WalletService.jdbcDataSource.getConnection();) {
                userId = DataBaseOperations.authorize(fwpAssertion.getAccountId(),
                                                      fwpAssertion.getSerialNumber(),
                                                      fwpAssertion.getPublicKey(),
                                                      connection);
            }

            StringBuilder html = new StringBuilder(
    
                "<div class='header'>Received by the Issuer</div>" +
    
                "<div style='display:flex;justify-content:center;margin-top:15pt'>" +
                  "<div class='comment'>")
            .append(ADServlet.sectionReference("seq-10"))
            .append(
                  ": If you have reached this far, the payment request has been verified " +
                  "to be authentic and a payment operation is being initiated." +
                  "<div style='margin-top:0.4em'>Thank you for testing!</div>" +
                  "</div>" +
                "</div>" +

                "<div style='overflow-x:auto;margin-top:1.5em'>" +
                  "<table class='tftable'>" +
  
                  "<tr><th colspan='2' style='text-align:center'>Transaction Core Data</th></tr>" +

                    "<tr><th>Amount</th><td>")
            .append(fwpPaymentRequest.getAmount())
            .append("</td></tr>" +
                    "<tr><th>Currency</th><td>")
            .append(fwpPaymentRequest.getCurrency())
            .append("</td></tr>" +
                    "<tr><th>Payee&nbsp;Account</th><td>")
            .append(pspRequest.getReceiveAccount())
            .append("</td></tr>" +
                    "<tr><th>Payer&nbsp;Account</th><td>")
            .append(fwpAssertion.getAccountId())
            .append("</td></tr>" +
                    "<tr><th>Payment&nbsp;Method</th><td>")
            .append(fwpAssertion.getPaymentMethod())
            .append("</td></tr>" +
                    "<tr><th>Transaction Id</th><td>")
            .append(String.format("%012d", transactionId++))
            .append("</td></tr>" +
                    "<tr><th>Time Stamp</th><td>")
            .append(ISODateTime.formatDateTime(new GregorianCalendar(),
                                               ISODateTime.UTC_NO_SUBSECONDS))
            .append("</td></tr>" +

                    "<tr><td colspan='2' style='background-color:white;border-width:0'></td></tr>" +

                    "<tr><th colspan='2' style='text-align:center'>Payee Information</th></tr>" +

                    "<tr><th>Common&nbsp;Name</th><td>")
            .append(fwpPaymentRequest.getPayeeName())
            .append("</td></tr>" +
                    "<tr><th>Host Name</th><td>")
            .append(fwpAssertion.getPayeeHost())
            .append("</td></tr>" +
                    "<tr><th>Request&nbsp;Id</th><td>")
            .append(fwpPaymentRequest.getRequestId())
            .append("</td></tr>" +
                    "<tr><th>Time Stamp</th><td>")
            .append(ISODateTime.formatDateTime(pspRequest.getTimeStamp(),
                                               ISODateTime.UTC_NO_SUBSECONDS))
            .append("</td></tr>" +
                    "<tr><td colspan='2' style='background-color:white;border-width:0'></td></tr>" +

                    "<tr><th colspan='2' style='text-align:center'>Payer Information</th></tr>" +

                    "<tr><th>User Id</th><td>")
            .append(userId)
            .append("</td></tr>" +
                    "<tr><th>Card Serial</th><td>")
            .append(fwpAssertion.getSerialNumber())
            .append("</td></tr>" +
                    "<tr><th>Client&nbsp;System</th><td>")
            .append(fwpAssertion.getOperatingSystem().getName())
            .append(' ')
            .append(fwpAssertion.getOperatingSystem().getVersion())
            .append(", ")
            .append(fwpAssertion.getUserAgent().getName())
            .append(' ')
            .append(fwpAssertion.getUserAgent().getVersion())
            .append("</td></tr>" +
                    "<tr><th>Auth&nbsp;Method</th><td>")
            .append(fwpAssertion.getUserAuthorizationMethod().toString())
            .append("</td></tr>" +
                    "<tr><th>IP&nbsp;Address</th><td>")
            .append(pspRequest.getClientIp())
            .append("</td></tr>" +
                    "<tr><th>Time Stamp</th><td>")
            .append(ISODateTime.formatDateTime(fwpAssertion.getTimeStamp(),
                                               ISODateTime.LOCAL_NO_SUBSECONDS))
            .append("</td></tr>" +
                  "</table>" +
                "</div>");
            
            HTML.standardPage(response, Actors.ISSUER, WalletCore.GO_HOME_JAVASCRIPT, html);
        } catch (Exception e) {
            HTML.errorPage(response, e);
        }
    }
    
    private void compare(String one, String two) throws GeneralSecurityException {
        if (!one.equals(two)) {
            throw new GeneralSecurityException("Compare failed for " + one + "=" + two);
        }
    }
}
