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

import java.nio.ByteBuffer;

import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;

import java.sql.Connection;

import java.util.GregorianCalendar;
import java.util.HashSet;

import java.util.logging.Logger;

import javax.servlet.ServletException;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.webpki.cbor.CBORAsymKeyDecrypter;
import org.webpki.cbor.CBORCryptoUtils;
import org.webpki.cbor.CBORDecrypter;
import org.webpki.cbor.CBORObject;

import org.webpki.crypto.ContentEncryptionAlgorithms;
import org.webpki.crypto.KeyEncryptionAlgorithms;

import org.webpki.fwp.FWPAssertionDecoder;
import org.webpki.fwp.FWPCrypto;
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
    
    public static final String ISSUER_REQUEST  = "issuerRequest";
    
    static final long AUTHORIZATION_MAX_AGE    = 600000;
    static final long AUTHORIZATION_MAX_FUTURE = 120000;
    
    static final CBORDecrypter decrypter = 
            new CBORAsymKeyDecrypter(new CBORAsymKeyDecrypter.KeyLocator() {

        @Override
        public PrivateKey locate(PublicKey optionalPublicKey,
                                 CBORObject optionalKeyId,
                                 KeyEncryptionAlgorithms keyEncryptionAlgorithm,
                                 ContentEncryptionAlgorithms contentEncryptionAlgorithm)
                 throws IOException, GeneralSecurityException {

            // Somewhat simplistic setup: a single encryption key
            if (optionalKeyId == null) {
                throw new GeneralSecurityException("Missing keyId");
            }
            if (!ApplicationService.issuerEncryptionKeyId.equals(
                    optionalKeyId)) {
                throw new GeneralSecurityException("Unknown keyId: " + optionalKeyId);
            }
            return ApplicationService.issuerEncryptionKey.getPrivate();
        }
        
    }).setTagPolicy(CBORCryptoUtils.POLICY.MANDATORY, new CBORCryptoUtils.Collector() {

        @Override
        public void foundData(CBORObject tag) 
                throws IOException, GeneralSecurityException {
            String typeUrl = tag.getTag().getObject().getArray().getObject(0).getTextString();
            if (!FWPCrypto.FWP_ESAD_OBJECT_ID.equals(typeUrl)) {
                throw new GeneralSecurityException("Unexpected type URL: " + typeUrl);
            }
        }

    });
    
    static long transactionId = 56807446412l;

    StringBuilder getUserValidation(HashSet<FWPCrypto.UserValidation> userValidationFlags) {
        StringBuilder userValidation = new StringBuilder();
        userValidation.append("Present=")
                      .append(userValidationFlags.contains(FWPCrypto.UserValidation.PRESENT))
                      .append(", Verified=")
                      .append(userValidationFlags.contains(FWPCrypto.UserValidation.VERIFIED));
        return userValidation;
    }
    
    void softError(HttpServletResponse response, String error, byte[] fwpAssertionBinary) 
        throws IOException, ServletException {
        StringBuilder html = new StringBuilder(
            "<div class='header'>Soft Error</div>" +
            "<div style='display:flex;justify-content:center;margin-top:15pt'>")
        .append(error)
        .append(
            " SAD (")
        .append(ADServlet.sectionReference("seq-4.3"))
        .append(
            ") object:</div>" +
            "<div class='staticbox'>")
        .append(HTML.encode(CBORObject.decode(fwpAssertionBinary).toString(), true))
        .append(
            "</div>");
        HTML.standardPage(response, Actors.ISSUER, WalletCore.GO_HOME_JAVASCRIPT, html);
    }
    
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
             
              // Decrypt ESAD returning SAD.
            byte[] fwpAssertionBinary = decrypter.decrypt(
                    CBORObject.decode(fwpJsonAssertion.getUserAuthorization()));
            // Succeeded.
            
            // Decode signed assertion (SAD).
            FWPAssertionDecoder fwpAssertion = new FWPAssertionDecoder(fwpAssertionBinary);
            // Succeeded => the data (SAD) is "technically" OK including the signature.
            
            // If the internal clock of an FWP client is severely out of sync, created
            // authorizations will be rejected.  This also makes clock manipulations
            // useless as attack vectors.
            long now = System.currentTimeMillis();
            long timeStamp = fwpAssertion.getTimeStamp().getTimeInMillis();
            long expirationTime = timeStamp + AUTHORIZATION_MAX_AGE;
            if (expirationTime < now) {
                softError(response, 
                          "Authorization max age (" +
                            (AUTHORIZATION_MAX_AGE / 1000) + 
                            "s) exceeded for",
                          fwpAssertionBinary);
                return;
            }
            if (timeStamp - AUTHORIZATION_MAX_FUTURE > now) {
                softError(response, 
                          "Authorization max future (" +
                            (AUTHORIZATION_MAX_FUTURE / 1000) + 
                            "s) exceeded for",
                          fwpAssertionBinary);
                return;
            }            

            // Check that the merchant request matches the authorization.
            fwpAssertion.verifyClaimedPaymentRequest(fwpPaymentRequest);

            // Check that the user haven't been phished.  Note that this check
            // depends on participation by the merchant's PSP.
            compare(decodedIssuerRequest.getPayeeHost(), fwpAssertion.getPayeeHost());
            
            // And of course, verify that the authorization belongs to a valid account!
            DataBaseOperations.AuthorizedInfo authorizedInfo;
            try (Connection connection = ApplicationService.jdbcDataSource.getConnection();) {
                authorizedInfo = DataBaseOperations.authorize(fwpAssertion.getSerialNumber(),
                                                              fwpAssertion.getAccountId(),
                                                              fwpAssertion.getPublicKey(),
                                                              connection);
            }

            // Create a cacheable SAD object that is uniquely (but momentarily)
            // representing a specific transaction request.
            //
            // The data needed to make this safe (=cause no false cache collisions),
            // in FWP depends on the following input
            // - The transaction (PRCD) request
            // . The host name derived from the URL of the FWP invocation
            // - The client generated time stamp
            // - The account specific payment credentials
            // - The FIDO signature counter
            // - The signature including public key
            // as well as that the request has been verified as genuine.
            //
            // The use of time stamped and signed authorization data together with
            // strict time limits on the verifier side, makes this scheme comparable
            // to WebAuthn, but considerably more flexible since such authorizations 
            // can pass any number of nodes without losing their "teeth".
            //
            // That user authorizations are carried out entirely locally makes merchant
            // integration of this part extremely simple.
            //
            // Due to the fact that payment requests represent discrete events that are
            // to be acted upon, rather than creating secure sessions with a client,
            // there is no need for dedicated authentication servers.
            //
            // Note that supporting IDEMPOTENT operation would require additional data like
            // - The hash of the entire request in order to verify input equivalence
            // - The full response for the initial successful request
            // since (then permitted, but still time limited) replays MUST NOT change anything
            // on the receiver side.
            ByteBuffer cacheableSadObject = ByteBuffer.wrap(fwpAssertionBinary);
            
            // Have this user authorization already been consumed?
            if (ReplayCache.INSTANCE.add(cacheableSadObject, expirationTime)) {
                logger.info("Replay of authorization token: " + cacheableSadObject.hashCode() +
                            ", accountId=" + fwpAssertion.getAccountId());
                softError(response,
                          "Replay of",
                          fwpAssertionBinary);
                return;
            }

            // Apparently this is a valid request.
            logger.info("Issuer verified: " + authorizedInfo.userId + 
                        ", token=" + cacheableSadObject.hashCode());

            StringBuilder html = new StringBuilder(
    
                "<form name='shoot' method='POST' action='issuerreq'>" +
                "<input type='hidden' name='" + ISSUER_REQUEST +
                "' value='")
            .append(HTML.encode(issuerRequest, false))
            .append(
                "'/>" +
                "</form>" +

                "<div class='header'>Payment Initiation</div>" +
    
                "<div style='display:flex;justify-content:center;margin-top:15pt'>" +
                  "<div class='comment'>")
            .append(ADServlet.sectionReference("seq-10"))
            .append(
                  ": If you have reached this far, the payment request has been verified " +
                  "for correctness by the <span class='actor'>Issuer</span> and a " +
                  "payment operation is being initiated." +
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
                    "<tr><th>Payment&nbsp;Network</th><td>")
            .append(fwpAssertion.getPaymentNetwork())
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

                    "<tr><th>User Name</th><td>")
            .append(HTML.encode(authorizedInfo.cardHolder, true))
            .append("</td></tr>" +
                    "<tr><th>User Id</th><td>")
            .append(authorizedInfo.userId)
            .append("</td></tr>" +
                    "<tr><th>Card Serial</th><td>")
            .append(fwpAssertion.getSerialNumber())
            .append("</td></tr>" +
                    "<tr><th>Client&nbsp;System</th><td>")
            .append(fwpAssertion.getOperatingSystem().getName())
            .append(fwpAssertion.getOperatingSystem().getVersion().equals("N/A") ? "" :
                " " + fwpAssertion.getOperatingSystem().getVersion())
            .append(", ")
            .append(fwpAssertion.getUserAgent().getName())
            .append(' ')
            .append(fwpAssertion.getUserAgent().getVersion())
            .append("</td></tr>" +
                    "<tr><th>User&nbsp;Validation</th><td>")
            .append(getUserValidation(fwpAssertion.getUserValidation()))
            .append("</td></tr>" +
                    "<tr><th>IP&nbsp;Address</th><td>")
            .append(pspRequest.getClientIpAddress())
            .append("</td></tr>" +
                    "<tr><th>Location</th><td>")
            .append("N/A")
            .append("</td></tr>" +
                    "<tr><th>Time Stamp</th><td>")
            .append(ISODateTime.formatDateTime(fwpAssertion.getTimeStamp(),
                                               ISODateTime.LOCAL_NO_SUBSECONDS))
            .append("</td></tr>" +
                  "</table>" +
                "</div>" +

                "<div style='display:flex;justify-content:center;margin-top:1.5em'>" +
                  "<div class='comment'>" +
                    "You may try to replay this transaction and see what happens. " +
                    "If you wait more than 10 minutes, the transaction request should " +
                    "be rejected because it has expired." +
                  "</div>" +
                "</div>" +
                    
                "<div style='display:flex;justify-content:center'>" +
                  "<div class='stdbtn' onclick=\"document.forms.shoot.submit()\">" +
                    "&quot;Replay&quot;" +
                  "</div>" +
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
