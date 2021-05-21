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

import java.sql.Connection;
import java.sql.SQLException;

import java.util.logging.Logger;
import java.util.logging.Level;

import javax.servlet.ServletOutputStream;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONObjectWriter;
import org.webpki.json.JSONOutputFormats;
import org.webpki.json.JSONParser;

import org.webpki.webutil.ServletUtil;

/**
 * Common FWP functions and constants.
 */
public class FWPCommon {

    // The center of it all...
    static final String WALLET_COOKIE            = "WALLET";

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
    
    static final int    FLAG_ED                  = 0x80;
    static final int    FLAG_AT                  = 0x40;
    
    // FIDO call data
    static final String CHALLENGE                = "challenge";
    static final String USER_ID                  = "userId";
    
    // Attribute returned to the client in case of a server-side error
    static final String ERROR_JSON               = "error";
    
    // Returned
    static final String CARD_HOLDER_JSON         = "cardHolder";
    // Returned FIDO
    static final String CREDENTIAL_ID            = "credentialId";
    static final String ATTESTATION_OBJECT       = "attestationObject";
    static final String CLIENT_DATA_JSON         = "clientDataJSON";
    static final String AUTHENTICATOR_DATA_JSON  = "authenticatorData";
    static final String SIGNATURE_JSON           = "signature";
    
    // Init/finalize phase session attributes
    static final String ATTR_REGISTER_DATA       = "registerdata";
    static final String ATTR_LOGIN_DATA          = "logindata";
    
    // When logged in this attribute contain the user ID.
    static final String ATTR_LOGGED_IN_USER      = "user";
    
    // Having a separate JS script is an option but this code
    // is 1) small 2) depends on global constants
    static final String FWP_JAVASCRIPT =

        "function b64urlToU8arr(code) {\n" +
        "  return Uint8Array.from(window.atob(" +
              "code.replace(/-/g, '+').replace(/_/g, '/') + '===='.substring(0, " +
              "(4 - (code.length % 4)) % 4)), c=>c.charCodeAt(0));\n" +
        "}\n" +

        "function arrBufToB64url(bytes) {\n" +
        "  return window.btoa(String.fromCharCode.apply(null, " +
              "new Uint8Array(bytes))).replace(/\\+/g, '-')" +
              ".replace(/\\//g, '_').replace(/=/g, '');\n" +
        "}\n" +
        
        "async function exchangeJSON(jsonObject, currentPhase) {\n" +
        "  try {\n" +
        "    jsonObject." + PHASE_JSON + " = currentPhase;\n" +
        "    const response = await fetch(serviceUrl, {\n" +
        "           headers: {\n" +
        "             'Content-Type': 'application/json'\n" +
        "           },\n" +
        "           method: 'POST',\n" +
        "           credentials: 'same-origin',\n" +
        "           body: JSON.stringify(jsonObject)\n" +
        "        });\n" +
        "    if (response.ok) {\n" +
        "      const jsonResult = await response.json();\n" +
        "      if (jsonResult." + PHASE_JSON + "!= currentPhase) {\n" +
        "        setError('Out of phase');\n" +
        "      }\n" +
        "      if (jsonResult." + ERROR_JSON + ") {\n" +
        "        setError(jsonResult." + ERROR_JSON + ");\n" +
        "      }\n" +
        "      return jsonResult;\n" +
        "    } else {\n" +
        "      setError('Server/network failure');\n" +
        "    }\n" + 
        "  } catch (error) {\n" +
        "    setError(error);\n" +
        "  }\n" +
        "}\n";

    static Logger logger = Logger.getLogger(FWPCommon.class.getName());

    static String getWalletCookie(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) for (Cookie cookie : cookies) {
            if (cookie.getName().equals(WALLET_COOKIE)) {
                return cookie.getValue();
            }
        }
        return null;
    }
    
    static boolean hasPaymentCards(HttpServletRequest request) throws SQLException {
        String claimedUserId = getWalletCookie(request);
        if (claimedUserId == null) {
            return false;
        }
        try (Connection connection = FWPService.jdbcDataSource.getConnection();) {
            return DataBaseOperations.hasPaymentCards(claimedUserId, connection);
        }
    }

    static JSONObjectReader getJSON(HttpServletRequest request) throws IOException {
        if (!request.getContentType().equals("application/json")) {
            logger.log(Level.SEVERE, "JSON MIME type expected");
            throw new IOException("Unexpected MIME type:" + request.getContentType());
        }
        JSONObjectReader parsedJson = JSONParser.parse(ServletUtil.getData(request));
//        if (FWPService.logging) {
            logger.info("User agent: " + request.getHeader("user-agent"));
            logger.info("Received: " + parsedJson.toString());
  //      }
        return parsedJson;
    }

    static void returnJSON(HttpServletResponse response, JSONObjectWriter json) throws IOException {
 //       if (FWPService.logging) {
            logger.info("To be returned: " + json.toString());
//        }
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

    static void softError(HttpServletResponse response, 
                          JSONObjectWriter json,
                          String errorMesseage) throws IOException {
        FWPCommon.returnJSON(response, json.setString(FWPCommon.ERROR_JSON, errorMesseage));
    }

    static void failed(String what) throws IOException {
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
}
