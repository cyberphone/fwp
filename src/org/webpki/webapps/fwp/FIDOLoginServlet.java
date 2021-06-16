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

import java.util.logging.Logger;
import java.util.logging.Level;

import javax.servlet.ServletException;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.webpki.crypto.CryptoRandom;

import org.webpki.fwp.FWPCrypto;

import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONObjectWriter;
import org.webpki.json.JSONParser;

import org.webpki.util.ArrayUtil;

/**
 * This Servlet is called by the LoginServlet SPA
 *
 */
public class FIDOLoginServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;
   
    static Logger logger = Logger.getLogger(FIDOLoginServlet.class.getName());

    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {
        try {
            // Get the input (request) data.
            JSONObjectReader requestJson = FWPWalletCore.getJSON(request);
            
            // Prepare for writing a response.
            JSONObjectWriter resultJson = new JSONObjectWriter();
            
            // The FIDO server is stateful and its state MUST be checked
            // with that of the client.
            String phase = requestJson.getString(FWPWalletCore.PHASE_JSON);

            // Tentative: return the same phase info as in the request.
            resultJson.setString(FWPWalletCore.PHASE_JSON, phase);
            
            // Get the enrolled user.
            String userId = FWPWalletCore.getWalletCookie(request);
            if (userId == null) {
                FWPWalletCore.softError(response, resultJson, "User ID missing, have you enrolled?");
                return;
            }
            
            // Determine where are in the process.
            if (phase.equals(FWPWalletCore.INIT_PHASE)) {

                // Firing up! We may have an old session but we don't really care.
                HttpSession session = request.getSession(true);
                
                // Clear existing login if any.
                session.removeAttribute(FWPWalletCore.ATTR_LOGGED_IN_USER);

                // We need to specify which FIDO key to use.                 
                try (Connection connection = FWPService.jdbcDataSource.getConnection();) {
                    // Get FIDO credentialId.
                    DataBaseOperations.CoreClientData coreClientData = 
                            DataBaseOperations.getCoreClientData(userId, connection);
                    if (coreClientData == null) {
                        FWPWalletCore.softError(response, resultJson, "User is missing, you need to reenroll");
                        return;
                    }
                    resultJson.setString(FWPCrypto.CREDENTIAL_ID, coreClientData.credentialId);
                }
 
                // - Provide FIDO challenge data
                byte[] challenge = CryptoRandom.generateRandom(32);
                resultJson.setBinary(FWPCrypto.CHALLENGE, challenge);

                // This what we send but we must also 
                session.setAttribute(FWPWalletCore.ATTR_LOGIN_DATA, new JSONObjectReader(resultJson));

            } else if (phase.equals(FWPWalletCore.FINALIZE_PHASE)) {
 
                // Login response! Now we must have an HTTP session.
                HttpSession session = request.getSession(false);
                if (session == null) {
                    FWPWalletCore.failed("Missing finalize session");
                }
                
                // Get the object holding the login session in progress.
                JSONObjectReader loginData = 
                        (JSONObjectReader) session.getAttribute(FWPWalletCore.ATTR_LOGIN_DATA);
                if (loginData == null) {
                    FWPWalletCore.failed("Login data missing");
                }

                // Check that we are in "sync".
                byte[] clientDataJSON = requestJson.getBinary(FWPCrypto.CLIENT_DATA_JSON_JSON);
                if (!ArrayUtil.compare(
                        JSONParser.parse(clientDataJSON).getBinary(FWPCrypto.CHALLENGE),
                    loginData.getBinary(FWPCrypto.CHALLENGE))) {
                    FWPWalletCore.failed("Challenge mismatch");
                }

                // Here we are supposed to the check the signature....
                byte[] authenticatorData = requestJson.getBinary(FWPCrypto.AUTHENTICATOR_DATA_JSON);
                byte[] signature = requestJson.getBinary(FWPCrypto.SIGNATURE_JSON);
                
                // Now, we have all client data needed to verify the signature.
                try (Connection connection = FWPService.jdbcDataSource.getConnection();) {
                    // Get the anticipated public key
                    DataBaseOperations.CoreClientData coreClientData = 
                            DataBaseOperations.getCoreClientData(userId, connection);
                    FWPCrypto.validateFidoSignature(
                            FWPCrypto.getWebPkiAlgorithm(
                                    FWPCrypto.publicKey2CoseSignatureAlgorithm(
                                            coreClientData.publicKey)), 
                            coreClientData.publicKey, 
                            authenticatorData, 
                            clientDataJSON, 
                            signature);
                }

                // We did it, set logged-in attribute.
                // Note that the session cookie is returned and set via the fetch() operation.
                session.setAttribute(FWPWalletCore.ATTR_LOGGED_IN_USER, userId);
                
                logger.info("Logged-in user: " + userId);
            } else {
                FWPWalletCore.failed("Unknown phase: " + phase);
            }
            FWPWalletCore.returnJSON(response, resultJson);

        } catch (Exception e) {
            String message = e.getMessage();
            logger.log(Level.SEVERE, FWPWalletCore.getStackTrace(e, message));
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            PrintWriter writer = response.getWriter();
            writer.print(message);
            writer.flush();
        }
    }
}
