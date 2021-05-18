/*
 *  Copyright 2006-2019 WebPKI.org (http://webpki.org).
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

import java.util.logging.Logger;
import java.util.logging.Level;

import javax.servlet.ServletException;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.webpki.crypto.CryptoRandom;

import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONObjectWriter;
import org.webpki.json.JSONParser;

import org.webpki.util.ArrayUtil;

/**
 * This Servlet is called from the LoginServlet SPA
 *
 */
public class FIDOLoginServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;
   
    static Logger logger = Logger.getLogger(FIDOLoginServlet.class.getName());

    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {
        try {
            // Get the input (request) data.
            JSONObjectReader requestJson = FWPCommon.getJSON(request);
            
            // Prepare for writing a response.
            JSONObjectWriter resultJson = new JSONObjectWriter();
            
            // Get the enrolled user.
            String userId = FWPCommon.getWalletCookie(request);
            if (userId == null) {
                resultJson.setString(FWPCommon.ERROR_JSON, "User ID missing, have you enrolled?");
                return;
            }
            
            // The FIDO server is stateful and its state MUST be checked
            // with that of the client.
            String phase = requestJson.getString(FWPCommon.PHASE_JSON);

            // Tentative: return the same phase info as in the request.
            resultJson.setString(FWPCommon.PHASE_JSON, phase);
            
            // Determine where are in the process.
            if (phase.equals(FWPCommon.INIT_PHASE)) {

                // Firing up! We may have an old session but we don't really care.
                HttpSession session = request.getSession(true);
                
                // Clear existing login if any.
                session.removeAttribute(FWPCommon.ATTR_LOGGED_IN_USER);

                // We need to specify which key to use.                 
                String keyHandle;
                try (Connection connection = FWPService.jdbcDataSource.getConnection();) {
                    // Get FIDO credentialId (which is called keyHandle in FWP).
                    keyHandle = DataBaseOperations.getKeyHandle(userId, connection);
                }
                resultJson.setString(FWPCommon.KEY_HANDLE_JSON, keyHandle);

                // - Provide FIDO challenge data
                byte[] challenge = CryptoRandom.generateRandom(32);
                resultJson.setBinary(FWPCommon.RP_CHALLENGE_JSON, challenge);

                // This what we send but we must also 
                session.setAttribute(FWPCommon.ATTR_LOGIN_DATA, new JSONObjectReader(resultJson));

            } else if (phase.equals(FWPCommon.FINALIZE_PHASE)) {
 
                // Login response! Now we must have an HTTP session.
                HttpSession session = request.getSession(false);
                if (session == null) {
                    FWPCommon.failed("Missing finalize session");
                }
                
                // Get the object holding the login session in progress.
                JSONObjectReader loginData = 
                        (JSONObjectReader) session.getAttribute(FWPCommon.ATTR_LOGIN_DATA);
                if (loginData == null) {
                    FWPCommon.failed("Login data missing");
                }

                // Check that we are in "sync".
                byte[] clientData = requestJson.getBinary(FWPCommon.CLIENT_DATA_JSON);
                JSONObjectReader clientDataJSON = JSONParser.parse(clientData);
                if (!ArrayUtil.compare(clientDataJSON.getBinary(FWPCommon.RP_CHALLENGE_JSON),
                    loginData.getBinary(FWPCommon.RP_CHALLENGE_JSON))) {
                    FWPCommon.failed("Challenge mismatch");
                }

                // Here we are supposed to the check the signature....
                byte[] authenticatorData = requestJson.getBinary(FWPCommon.AUTHENTICATOR_DATA_JSON);
                byte[] signature = requestJson.getBinary(FWPCommon.SIGNATURE_JSON);

                // We did it, set logged-in attribute.
                session.setAttribute(FWPCommon.ATTR_LOGGED_IN_USER, userId);
                
                logger.info("Logged-in user: " + userId);
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
