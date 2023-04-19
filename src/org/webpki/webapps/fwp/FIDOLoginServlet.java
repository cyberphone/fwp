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

import java.security.PublicKey;

import java.sql.Connection;

import java.util.Arrays;

import java.util.logging.Level;
import java.util.logging.Logger;

import javax.servlet.ServletException;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.webpki.cbor.CBORObject;
import org.webpki.cbor.CBORPublicKey;

import org.webpki.crypto.CryptoRandom;

import org.webpki.fwp.FWPCrypto;

import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONObjectWriter;
import org.webpki.json.JSONParser;

/**
 * This Servlet is called by the LoginServlet SPA
 *
 */
public class FIDOLoginServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;
   
    static Logger logger = Logger.getLogger(FIDOLoginServlet.class.getName());
    
    static final String MISSING_ENROLL = "User ID missing, have you enrolled?";

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
            
            // Get the enrolled user.
            String userId = WalletCore.getWalletCookie(request);
            if (userId == null) {
                WalletCore.softError(response, resultJson, MISSING_ENROLL);
                return;
            }
            
            // Determine where are in the process.
            if (phase.equals(WalletCore.INIT_PHASE)) {

                // Firing up! We may have an old session but we don't really care.
                HttpSession session = request.getSession(true);
                
                // Clear existing login if any.
                session.removeAttribute(WalletCore.ATTR_LOGGED_IN_USER);

                // We need to specify which FIDO key to use.                 
                try (Connection connection = ApplicationService.jdbcDataSource.getConnection();) {
                    // Get FIDO credentialId.
                    DataBaseOperations.CoreClientData coreClientData = 
                            DataBaseOperations.getCoreClientData(userId, connection);
                    if (coreClientData == null) {
                        WalletCore.softError(response, resultJson, "User is missing, you need to reenroll");
                        return;
                    }
                    resultJson.setBinary(FWPCrypto.CREDENTIAL_ID, coreClientData.credentialId);
                }
 
                // - Provide FIDO challenge data
                byte[] challenge = CryptoRandom.generateRandom(32);
                resultJson.setBinary(FWPCrypto.CHALLENGE, challenge);

                // This what we send but we must also 
                session.setAttribute(WalletCore.ATTR_LOGIN_DATA, new JSONObjectReader(resultJson));

            } else if (phase.equals(WalletCore.FINALIZE_PHASE)) {
 
                // Login response! Now we must have an HTTP session.
                HttpSession session = request.getSession(false);
                if (session == null) {
                    WalletCore.failed("Missing finalize session");
                }
                
                // Get the object holding the login session in progress.
                JSONObjectReader loginData = 
                        (JSONObjectReader) session.getAttribute(WalletCore.ATTR_LOGIN_DATA);
                if (loginData == null) {
                    WalletCore.failed("Login data missing");
                }

                // Check that we are in "sync".
                byte[] clientDataJSON = requestJson.getBinary(FWPCrypto.CLIENT_DATA_JSON);
                if (!Arrays.equals(
                        JSONParser.parse(clientDataJSON).getBinary(FWPCrypto.CHALLENGE),
                    loginData.getBinary(FWPCrypto.CHALLENGE))) {
                    WalletCore.failed("Challenge mismatch");
                }

                // Here we are supposed to the check the signature....
                byte[] authenticatorData = requestJson.getBinary(FWPCrypto.AUTHENTICATOR_DATA);
                session.setAttribute(WalletCore.ATTR_LOGIN_DATA, authenticatorData);
                byte[] signature = requestJson.getBinary(FWPCrypto.SIGNATURE);
                
                // Now, we have all client data needed to verify the signature.
                try (Connection connection = ApplicationService.jdbcDataSource.getConnection();) {
                    // Get the anticipated public key
                    DataBaseOperations.CoreClientData coreClientData = 
                            DataBaseOperations.getCoreClientData(userId, connection);
                    PublicKey publicKey = 
                            CBORPublicKey.convert(CBORObject.decode(coreClientData.cosePublicKey));
                    FWPCrypto.validateFidoSignature(
                            FWPCrypto.getWebPkiAlgorithm(
                                    FWPCrypto.publicKey2CoseSignatureAlgorithm(publicKey)), 
                            publicKey, 
                            authenticatorData, 
                            clientDataJSON, 
                            signature);
                }
                
                // User statistics...
                try (Connection connection = ApplicationService.jdbcDataSource.getConnection();) {
                    DataBaseOperations.updateUserStatistics(userId, true, connection);
                }
                // We did it, set logged-in attribute.
                // Note that the session cookie is returned and set via the fetch() operation.
                session.setAttribute(WalletCore.ATTR_LOGGED_IN_USER, userId);
                
                // Refresh the persistent cookie. 
                FIDOEnrollServlet.setWalletCookie(response, userId);

                logger.info("Logged-in user: " + userId);
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
