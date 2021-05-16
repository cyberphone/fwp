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

import java.util.UUID;

import java.util.logging.Logger;
import java.util.logging.Level;

import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.webpki.crypto.CryptoRandom;

import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONObjectWriter;
import org.webpki.json.JSONOutputFormats;
import org.webpki.json.JSONParser;

import org.webpki.webutil.ServletUtil;
/**
 * This Servlet is called from the EnrollServlet SPA
 *
 */
public class FIDOEnrollServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;
    
    static final String HTTP_PRAGMA              = "Pragma";
    static final String HTTP_EXPIRES             = "Expires";
    static final String HTTP_ACCEPT_HEADER       = "Accept";
    static final String HTTP_CONTENT_TYPE_HEADER = "Content-Type";

    static final String JSON_CONTENT_TYPE        = "application/json";
    
    // Used by the client and server to keep sync
    static final String PHASE_JSON               = "phase";
    // Arguments to PHASE
    static final String INIT_PHASE               = "init";
    static final String FINALIZE_PHASE           = "finalize";
    
    // Additional JSON elements
    static final String RP_CHALLENGE_JSON        = "challenge";
    static final String RP_USER_ID               = "userId";
    
    // Returned
    static final String CARD_HOLDER_JSON         = "cardHolder";
    static final String KEY_HANDLE_JSON          = "keyHandle";
    
    // Init phase session data
    static final String REGISTER_DATA            = "regdata";

    static Logger logger = Logger.getLogger(FIDOEnrollServlet.class.getName());

    static JSONObjectReader getJSON(HttpServletRequest request) throws IOException {
        if (!request.getContentType().equals("application/json")) {
            logger.log(Level.SEVERE, "JSON MIME type expected");
            throw new IOException("Unexpected MIME type:" + request.getContentType());
        }
        JSONObjectReader parsedJson = JSONParser.parse(ServletUtil.getData(request));
//        if (FWPService.logging) {
            logger.info("Received: " + parsedJson.toString());
  //      }
        return parsedJson;
    }

    static void returnJSON(HttpServletResponse response, JSONObjectWriter json) throws IOException {
        if (FWPService.logging) {
            logger.info("To be returned: " + json.toString());
        }
        byte[] rawData = json.serializeToBytes(JSONOutputFormats.NORMALIZED);
        response.setContentType(JSON_CONTENT_TYPE);
        response.setHeader(HTTP_PRAGMA, "No-Cache");
        response.setDateHeader(HTTP_EXPIRES, 0);
        // Chunked data seems unnecessary here
        response.setContentLength(rawData.length);
        ServletOutputStream serverOutputStream = response.getOutputStream();
        serverOutputStream.write(rawData);
        serverOutputStream.flush();
    }
    
    void failed(String what) throws IOException {
        throw new IOException(what);
    }
    
    static String getStackTrace(Exception e, String message) {
        StringBuilder error = new StringBuilder()
                .append(e.getClass().getName())
                .append(": ")
                .append(message);
        StackTraceElement[] st = e.getStackTrace();
        int length = st.length;
        if (length > 20) {
            length = 20;
        }
        for (int i = 0; i < length; i++) {
            String entry = st[i].toString();
            error.append("\n  at " + entry);
            if (entry.contains(".HttpServlet")) {
                break;
            }
        }
        return error.toString();
    }

    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {
        try {
            // Get the input (request) data.
            JSONObjectReader requestJson = getJSON(request);
            
            // Prepare for writing a response.
            JSONObjectWriter resultJson = new JSONObjectWriter();
            
            // The FIDO server is stateful and its state MUST be checked
            // with that of the client.
            String phase = requestJson.getString(PHASE_JSON);

            // Tentative: return the same phase info as in the request.
            resultJson.setString(PHASE_JSON, phase);
            
            // Determine where are in the process.
            if (phase.equals(INIT_PHASE)) {

                // Firing up! We may have an old session but we don't really care.
                HttpSession session = request.getSession(true);
                
                // Due to limitations in FIDO credential management we
                // reuse an existing user ID if there is one.
                String userId = EnrollServlet.getWalletCookie(request);
                if (userId == null) {
                    userId = UUID.randomUUID().toString();
                    logger.info("Created new user: " + userId);
                }

                // - Provide FIDO register challenge data
                byte[] challenge = CryptoRandom.generateRandom(32);
                resultJson.setBinary(RP_CHALLENGE_JSON, challenge);

                // We use a UUID as the sole entry in the database and tie
                // the credentials and (a single) FIDO authenticator to that.
                resultJson.setString(RP_USER_ID, userId);
                
                // This what we send but we must also 
                session.setAttribute(REGISTER_DATA, new JSONObjectReader(resultJson));

            } else if (phase.equals(FINALIZE_PHASE)) {
 
                // Finalizing! Now we must have a session 
                HttpSession session = request.getSession(false);
                if (session == null) {
                    failed("Missing finalize session");
                }
                JSONObjectReader registerData = (JSONObjectReader) session.getAttribute(REGISTER_DATA);
                if (registerData == null) {
                    failed("Enrollment register data missing");
                }
                String userId = registerData.getString(RP_USER_ID);

                // Get card holder name.
                String cardHolder = requestJson.getString(CARD_HOLDER_JSON);
                
                // Get credintialId.  Note: it is called "KeyHandle" in the database
                // to match the FWP specification.
                String keyHandleB64 = requestJson.getString(KEY_HANDLE_JSON);
                
                // Waiting for key implementation
                byte[] fakeCosePublicKey = new byte[100];
                for (int i = 0; i < fakeCosePublicKey.length; i++) fakeCosePublicKey[i] = (byte) i;

if (cardHolder.equals("bad")) failed(cardHolder);
                
                // Assuming that everything has been verified we are finally ready
                // issuing the requested payment credentials.
 
                // Now perform all the database chores.
                try (Connection connection = FWPService.jdbcDataSource.getConnection();) {
                   // Store basic data.
                    DataBaseOperations.initiateUserAccount(userId, 
                                                           cardHolder,
                                                           keyHandleB64,
                                                           fakeCosePublicKey,
                                                           connection);
                }

                // To enable the Web emulator, put the UUID in a persistent cookie. 
                Cookie walletCookie = new Cookie(EnrollServlet.WALLET_COOKIE, userId);
                walletCookie.setMaxAge(8640000);  // 100 days.
                walletCookie.setSecure(true);
                response.addCookie(walletCookie);

                logger.info("Initiated user: " + userId);
            } else {
                failed("Unknown phase: " + phase);
            }
            returnJSON(response, resultJson);

        } catch (Exception e) {
            String message = e.getMessage();
            logger.log(Level.SEVERE, getStackTrace(e, message));
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            PrintWriter writer = response.getWriter();
            writer.print(message);
            writer.flush();
        }
    }
}
