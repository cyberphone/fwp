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

import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.io.PrintWriter;

import java.sql.Connection;

import java.util.UUID;

import java.util.logging.Logger;
import java.util.logging.Level;

import javax.servlet.ServletException;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.webpki.cbor.CBORObject;
import org.webpki.cbor.CBORPublicKey;

import org.webpki.crypto.CryptoRandom;

import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONObjectWriter;
import org.webpki.json.JSONParser;

import org.webpki.util.ArrayUtil;

/**
 * This Servlet is called from the EnrollServlet SPA
 *
 */
public class FIDOEnrollServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;
   
    static Logger logger = Logger.getLogger(FIDOEnrollServlet.class.getName());

    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {
        try {
            // Get the input (request) data.
            JSONObjectReader requestJson = FWPCommon.getJSON(request);
            
            // Prepare for writing a response.
            JSONObjectWriter resultJson = new JSONObjectWriter();
            
            // The FIDO server is stateful and its state MUST be checked
            // with that of the client.
            String phase = requestJson.getString(FWPCommon.PHASE_JSON);

            // Tentative: return the same phase info as in the request.
            resultJson.setString(FWPCommon.PHASE_JSON, phase);
            
            // Determine where are in the process.
            if (phase.equals(FWPCommon.INIT_PHASE)) {

                // Firing up! We may have an old session but we don't really care.
                HttpSession session = request.getSession(true);
                
                // Due to limitations in FIDO credential management we
                // reuse an existing user ID if there is one.
                String userId = FWPCommon.getWalletCookie(request);
                if (userId == null) {
                    userId = UUID.randomUUID().toString();
                    logger.info("Created new user: " + userId);
                }

                // - Provide FIDO register challenge data
                byte[] challenge = CryptoRandom.generateRandom(32);
                resultJson.setBinary(FWPCommon.CHALLENGE, challenge);

                // We use a UUID as the sole entry in the database and tie
                // the credentials and (a single) FIDO authenticator to that.
                resultJson.setString(FWPCommon.USER_ID, userId);
                
                // This what we send but we must also 
                session.setAttribute(FWPCommon.ATTR_REGISTER_DATA, new JSONObjectReader(resultJson));

            } else if (phase.equals(FWPCommon.FINALIZE_PHASE)) {
 
                // Finalizing! Now we must have an HTTP session.
                HttpSession session = request.getSession(false);
                if (session == null) {
                    FWPCommon.failed("Missing finalize session");
                }
                JSONObjectReader registerData = 
                        (JSONObjectReader) session.getAttribute(FWPCommon.ATTR_REGISTER_DATA);
                if (registerData == null) {
                    FWPCommon.failed("Enrollment register data missing");
                }

                // Check that we are in "sync".
                byte[] clientDataJSON = requestJson.getBinary(FWPCommon.CLIENT_DATA_JSON);
                if (!ArrayUtil.compare(
                        JSONParser.parse(clientDataJSON).getBinary(FWPCommon.CHALLENGE),
                        registerData.getBinary(FWPCommon.CHALLENGE))) {
                    FWPCommon.failed("Challenge mismatch");
                }

                // User ID is central.
                String userId = registerData.getString(FWPCommon.USER_ID);

                // Get card holder name.
                String cardHolder = requestJson.getString(FWPCommon.CARD_HOLDER_JSON);
                
                // Get credintialId.  To simplify things a bit we keep it in B64U notation.
                String credentialId = requestJson.getString(FWPCommon.CREDENTIAL_ID);
                
                // The object that holds it all but we don't care about attestations yet...
                byte[] attestationObject = requestJson.getBinary(FWPCommon.ATTESTATION_OBJECT);

                // Digging out the COSE public key is somewhat difficult...
                byte[] authData = CBORObject.decode(attestationObject)
                        .getTextStringMap().getObject("authData").getByteString();
                if ((authData[32] & (FWPCommon.FLAG_AT + FWPCommon.FLAG_ED)) != FWPCommon.FLAG_AT) {
                    FWPCommon.softError(response, resultJson, 
                                        "Unsupported authData flags: " + authData[32]);
                    return;
                }
                int i = 32 + 1 + 4 + 16;
                int credentialIdLength = (authData[i++] << 8) + authData[i++];
                int offset = i + credentialIdLength;
                byte[] rawPublicKey = new byte[authData.length - offset];
                System.arraycopy(authData, offset, rawPublicKey, 0, rawPublicKey.length);

                // Verify that we actually got a genuine public key.
                CBORPublicKey.decode(CBORObject.decode(rawPublicKey));

// Test only
if (cardHolder.equals("-1")) FWPCommon.failed(cardHolder);  // Hard server error
if (cardHolder.equals("-2")) { // Soft server error
    FWPCommon.softError(response, resultJson, "Sorry, something isn't as it should");
    return;
}
                
                // Assuming that everything has been verified we are finally ready
                // issuing the requested payment credentials.
 
                // A single call will do the trick.
                try (Connection connection = FWPService.jdbcDataSource.getConnection();) {
                    // Store basic data.
                    DataBaseOperations.initiateUserAccount(userId, 
                                                           cardHolder,
                                                           credentialId,
                                                           rawPublicKey,
                                                           connection);
                }

                // To enable the Web emulator, put the UUID in a persistent cookie. 
                Cookie walletCookie = new Cookie(FWPCommon.WALLET_COOKIE, userId);
                walletCookie.setMaxAge(8640000);  // 100 days.
                walletCookie.setSecure(true);
                response.addCookie(walletCookie);

                logger.info("Initiated user: " + userId);
            } else {
                FWPCommon.failed("Unknown phase: " + phase);
            }
            FWPCommon.returnJSON(response, resultJson);

        } catch (Exception e) {
            String message = e.getMessage();
            logger.log(Level.SEVERE, FWPCommon.getStackTrace(e, message));
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            PrintWriter writer = response.getWriter();
            writer.print(message);
            writer.flush();
        }
    }
}
