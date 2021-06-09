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

import org.webpki.cbor.CBORMap;
import org.webpki.cbor.CBORObject;

import org.webpki.crypto.HashAlgorithms;

import org.webpki.fwp.FWPCrypto;

import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONObjectWriter;
import org.webpki.json.JSONParser;

import org.webpki.util.ArrayUtil;

/**
 * This Servlet is called by the PayServlet SPA
 *
 */
public class FIDOPayServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;
   
    static Logger logger = Logger.getLogger(FIDOPayServlet.class.getName());

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
            
            // Get the enrolled user.
            String userId = FWPCommon.getWalletCookie(request);
            if (userId == null) {
                FWPCommon.softError(response, resultJson, "User ID missing, have you enrolled?");
                return;
            }
            
            // Determine where are in the process.
            if (phase.equals(FWPCommon.INIT_PHASE)) {

                // Firing up! We may have an old session but we don't really care.
                HttpSession session = request.getSession(true);
                
                // We need to specify which FIDO key to use.                 
                DataBaseOperations.CoreClientData coreClientData;
                try (Connection connection = FWPService.jdbcDataSource.getConnection();) {
                    // Get FIDO credentialId.
                    coreClientData = 
                            DataBaseOperations.getCoreClientData(userId, connection);
                    if (coreClientData == null) {
                        FWPCommon.softError(response, resultJson, "User is missing, you need to reenroll");
                        return;
                    }
                    resultJson.setString(FWPCrypto.CREDENTIAL_ID, coreClientData.credentialId);
                }
/* 
                // Create the preliminary FWP assertion.
                byte[] unsignedAssertion = FWPCrypto.createDataToBeSigned(
                        requestJson.getObject(FWPCommon.FWP_INPUT),
                        coreClientData.publicKey);
*/
 byte[]unsignedAssertion = null;

                // Need to save it for completion by FIDO.
                resultJson.setBinary(FWPCommon.FWP_ASSERTION, unsignedAssertion);

                // Make FIDO sign a hash of the unsigned assertion.
                resultJson.setBinary(FWPCrypto.CHALLENGE, 
                                     HashAlgorithms.SHA256.digest(unsignedAssertion));

                // This what we send but we must also read and verify it.
                session.setAttribute(FWPCommon.ATTR_PAY_DATA, new JSONObjectReader(resultJson));

            } else if (phase.equals(FWPCommon.FINALIZE_PHASE)) {
 
                // Login response! Now we must have an HTTP session.
                HttpSession session = request.getSession(false);
                if (session == null) {
                    FWPCommon.failed("Missing finalize session");
                }
                
                // Get the object holding the payment authorization session in progress.
                JSONObjectReader payData = 
                        (JSONObjectReader) session.getAttribute(FWPCommon.ATTR_PAY_DATA);
                if (payData == null) {
                    FWPCommon.failed("Pay data missing");
                }

                // Check that we are in "sync".
                byte[] clientDataJSON = requestJson.getBinary(FWPCrypto.CLIENT_DATA_JSON);
                if (!ArrayUtil.compare(
                        JSONParser.parse(clientDataJSON).getBinary(FWPCrypto.CHALLENGE),
                    payData.getBinary(FWPCrypto.CHALLENGE))) {
                    FWPCommon.failed("Challenge mismatch");
                }

                // Now we need to assemble the completed FWP assertion.
                byte[] authenticatorData = requestJson.getBinary(FWPCrypto.AUTHENTICATOR_DATA_JSON);
                byte[] signature = requestJson.getBinary(FWPCrypto.SIGNATURE_JSON);
                CBORMap unsignedAssertion = 
                        CBORObject.decode(payData.getBinary(FWPCommon.FWP_ASSERTION)).getMap();
/*  
                resultJson.setBinary(FWPCommon.FWP_ASSERTION,
                                     FWPCrypto.finalizeAssertion(unsignedAssertion,
                                                                    authenticatorData,
                                                                    clientDataJSON,
                                                                    signature));
*/                
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
