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
import java.io.PrintWriter;

import java.sql.Connection;

import java.util.Arrays;
import java.util.UUID;

import java.util.logging.Logger;
import java.util.logging.Level;

import javax.servlet.ServletException;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.webpki.crypto.CryptoRandom;

import org.webpki.fwp.FWPCrypto;

import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONObjectWriter;
import org.webpki.json.JSONParser;

/**
 * This Servlet is called by the EnrollServlet SPA
 *
 */
public class FIDOEnrollServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;
    
    static void setWalletCookie(HttpServletResponse response, String userId) {
        Cookie walletCookie = new Cookie(WalletCore.WALLET_COOKIE, userId);
        walletCookie.setMaxAge(8640000);  // 100 days.
        walletCookie.setSecure(true);
        response.addCookie(walletCookie);
    }
   
    static Logger logger = Logger.getLogger(FIDOEnrollServlet.class.getName());

    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {
        try {
            // Get the input (request) data.
            JSONObjectReader requestJson = WalletCore.getJSON(request);
            
            // Prepare for writing a response.
            JSONObjectWriter resultJson = new JSONObjectWriter();
            
            // The FIDO server is stateful and its state MUST be checked
            // with that of the client.
            String phase = requestJson.getString(WalletCore.PHASE_JSON);

            // Tentative: return the same phase info as in the request.
            resultJson.setString(WalletCore.PHASE_JSON, phase);
            
            // Determine where are in the process.
            if (phase.equals(WalletCore.INIT_PHASE)) {

                // Firing up! We may have an old session but we don't really care.
                HttpSession session = request.getSession(true);
                
                // Get the card holder
                String cardHolder = requestJson.getString(WalletCore.CARD_HOLDER);
                
                // Due to limitations in FIDO credential management we
                // reuse an existing user ID if there is one.
                String userId = WalletCore.getWalletCookie(request);
                if (userId == null) {
                    userId = UUID.randomUUID().toString();
                }

                // - Provide FIDO register challenge data
                byte[] challenge = CryptoRandom.generateRandom(32);
                resultJson.setBinary(FWPCrypto.CHALLENGE, challenge);

                // We use a UUID as the sole entry in the database and tie payment
                // credentials and (a single) FIDO authenticator to that.
                resultJson.setString(FWPCrypto.USER_ID, userId);
                
                // And the card holder.  Also displayed by WebAuthn
                resultJson.setString(WalletCore.CARD_HOLDER, cardHolder);
                
                // We must also keep a copy of emitted data in a server session.
                // The client can only partially be trusted!
                session.setAttribute(WalletCore.ATTR_REGISTER_DATA, 
                                     new JSONObjectReader(resultJson));

            } else if (phase.equals(WalletCore.FINALIZE_PHASE)) {
 
                // Finalizing! Now we must have an HTTP session.
                HttpSession session = request.getSession(false);
                if (session == null) {
                    WalletCore.failed("Missing finalize session");
                }
                JSONObjectReader registerData = 
                        (JSONObjectReader) session.getAttribute(WalletCore.ATTR_REGISTER_DATA);
                if (registerData == null) {
                    WalletCore.failed("Enrollment register data missing");
                }

                // Check that we are in "sync".
                byte[] clientDataJSON = requestJson.getBinary(FWPCrypto.CLIENT_DATA_JSON);
                if (!Arrays.equals(
                        JSONParser.parse(clientDataJSON).getBinary(FWPCrypto.CHALLENGE),
                        registerData.getBinary(FWPCrypto.CHALLENGE))) {
                    WalletCore.failed("Challenge mismatch");
                }

                // User ID is central.
                String userId = registerData.getString(FWPCrypto.USER_ID);

                // Get card holder name.
                String cardHolder = registerData.getString(WalletCore.CARD_HOLDER);

                // The object that holds it all but we don't care about attestations yet...
                byte[] attestationObject = requestJson.getBinary(FWPCrypto.ATTESTATION_OBJECT);

                // But we do extract the core data...
                FWPCrypto.UserCredential userCredential = 
                        FWPCrypto.extractUserCredential(attestationObject);

 // Test only
if (cardHolder.equals("-1")) WalletCore.failed(cardHolder);  // Hard server error
if (cardHolder.equals("-2")) { // Soft server error
    WalletCore.softError(response, resultJson, "Sorry, something isn't as it should");
    return;
}
                
                // Assuming that everything has been verified we are finally ready
                // issuing the requested payment credentials.
 
                // A single call will do the trick.
                try (Connection connection = ApplicationService.jdbcDataSource.getConnection();) {
                    // Store basic data.
                    DataBaseOperations.initiateUserAccount(userId, 
                                                           cardHolder,
                                                           userCredential.credentialId,
                                                           request.getServerName(),
                                                           userCredential.rawCosePublicKey,
                                                           request.getRemoteAddr(),
                                                           connection);
                }

                // To enable the Web emulator, put the UUID in a persistent cookie. 
                setWalletCookie(response, userId);

                logger.info("Successfully enrolled user: " + userId);
            } else {
                WalletCore.failed("Unknown phase: " + phase);
            }
            WalletCore.returnJSON(response, resultJson);

        } catch (Exception e) {
            String message = e.getMessage();
            logger.log(Level.SEVERE, WalletCore.getStackTrace(e, message));
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            PrintWriter writer = response.getWriter();
            writer.print(message);
            writer.flush();
        }
    }
}
