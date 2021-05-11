/*
 *  Copyright 2018-2020 WebPKI.org (http://webpki.org).
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

import java.net.URLEncoder;

import java.security.KeyPair;

import java.util.logging.Logger;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.webpki.crypto.AlgorithmPreferences;
import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.crypto.HmacAlgorithms;
import org.webpki.crypto.SignatureAlgorithms;

import org.webpki.jose.jws.JWSAsymKeySigner;
import org.webpki.jose.jws.JWSHmacSigner;
import org.webpki.jose.jws.JWSSigner;

import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONObjectWriter;
import org.webpki.json.JSONOutputFormats;
import org.webpki.json.JSONParser;

import org.webpki.util.Base64;
import org.webpki.util.Base64URL;
import org.webpki.util.DebugFormatter;
import org.webpki.util.PEMDecoder;

public class EnrollServlet extends HttpServlet {
    
    static Logger logger = Logger.getLogger(EnrollServlet.class.getName());

    private static final long serialVersionUID = 1L;

    // HTML form arguments
    static final String PRM_JSON_DATA    = "json";
    
    static final String PRM_JWS_EXTRA    = "xtra";

    static final String PRM_SECRET_KEY   = "sec";

    static final String PRM_PRIVATE_KEY  = "priv";

    static final String PRM_CERT_PATH    = "cert";

    static final String PRM_ALGORITHM    = "alg";
    static final String CARD_HOLDER_NAME    = "siglbl";

    static final String FLG_CERT_PATH    = "cerflg";
    static final String FLG_JAVASCRIPT   = "jsflg";
    static final String FLG_JWK_INLINE   = "jwkflg";
    
    static final String DEFAULT_ALG      = "ES256";
    static final String DEFAULT_CARD_HOLDER_NAME  = "Anonymous Tester &#x1f638;";
    
    static final String WALLET_COOKIE    = "WALLET";
    
    static boolean hasWalletCookie(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) for (Cookie cookie : cookies) {
            if (cookie.getName().equals(WALLET_COOKIE)) {
                return true;
            }
        }
        return false;
    }
    
    public void doGet(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {
        StringBuilder js = new StringBuilder("'use strict';\n");
        StringBuilder html = new StringBuilder(hasWalletCookie(request) ?
            "<div class='header'>Enroll Payment Cards</div>" +
            "<div style='display:flex;justify-content:center;margin-top:15pt;color=red;font-weight=bold'>" +
            "You already have enrolled payment cards, what do you want to do with them?" +
            "</div>" +
            "<div style='display:flex;justify-content:center'><table>" +
            "<tr><td><div class='multibtn' onclick=\"document.location.href='hash'\">" +
            "Buy Something!" +
            "</div></td></tr>" +
            "<tr><td><div class='multibtn' onclick=\"document.location.href='disenroll'\">" +
            "Delete Cards..." +
            "</div></td></tr>" +
            "</table></div>"
                                 :
            "<form name='shoot' method='POST' action='enroll'>" +
            "<div class='header'>Enroll Payment Cards</div>" +
            "<div style='display:flex;justify-content:center;margin-top:15pt'>" +
            "<table display='inline-block'><tr><td>Card Holder:</td></tr><tr><td>" +
            "<input type='text' name='" + CARD_HOLDER_NAME + "' id='" + CARD_HOLDER_NAME + "' " +
            "maxlength='50' value='" + DEFAULT_CARD_HOLDER_NAME + 
            "' style='background-color:#def7fc;padding:2pt 3pt' autofocus>" +
            "</td></tr></table>" +
            "</div>" +
            "<div style='display:flex;justify-content:center'>" +
            "<div class='stdbtn' onclick=\"document.forms.shoot.submit()\">" +
            "Start Enrollment!" +
            "</div>" +
            "</div>" +
                "</form>");
        js.append("// hi\n");
        HTML.standardPage(response, 
                         js.toString(),
                         html);
    }
    
    static String getParameter(HttpServletRequest request, String parameter) throws IOException {
        String string = request.getParameter(parameter);
        if (string == null) {
            throw new IOException("Missing data for: "+ parameter);
        }
        return string.trim();
    }
    
    static byte[] getBinaryParameter(HttpServletRequest request, String parameter) throws IOException {
        return getParameter(request, parameter).getBytes("utf-8");
    }

    static String getTextArea(HttpServletRequest request, String name)
            throws IOException {
        String string = getParameter(request, name);
        StringBuilder s = new StringBuilder();
        for (char c : string.toCharArray()) {
            if (c != '\r') {
                s.append(c);
            }
        }
        return s.toString();
    }

    static byte[] decodeSymmetricKey(String keyString) throws IOException {
        return keyString.startsWith("@") ? 
                   keyString.substring(1).getBytes("utf-8") 
                                         : 
                  DebugFormatter.getByteArrayFromHex(keyString);
    }

    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {
        try {
            request.setCharacterEncoding("utf-8");
            String cardHolderName = getParameter(request, CARD_HOLDER_NAME);
            StringBuilder js = new StringBuilder("'use strict';\n");
                StringBuilder html = new StringBuilder(
                        "<div class='header'>Enrollment Succeeded</div>" +
                        "<div style='display:flex;justify-content:center;margin-top:15pt'>" +
                        "You did it!" +
                        "</div>" +
                        "<div style='display:flex;justify-content:center'>" +
                        "<div class='stdbtn' onclick=\"document.location.href='hash'\">" +
                        "Buy Something..." +
                        "</div>" +
                        "</div>");
                js.append("// hi\n");
                Cookie walletCookie = new Cookie(WALLET_COOKIE,"data");
                walletCookie.setMaxAge(10000);
                response.addCookie(walletCookie);
                HTML.standardPage(response, 
                                 js.toString(),
                                 html);
        } catch (Exception e) {
            HTML.errorPage(response, e);
        }
    }
}
