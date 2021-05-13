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

public class WalletAdminServlet extends HttpServlet {
    
    static Logger logger = Logger.getLogger(WalletAdminServlet.class.getName());

    private static final long serialVersionUID = 1L;
    
    static final String WALLET_ADMIN_BUTTON =
            "<tr><td><div class='multibtn' onclick=\"document.location.href='walletadmin'\">" +
                "Wallet Administration..." +
            "</div></td></tr>" +
            "</table>";

    
    public void doGet(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {
        StringBuilder js = new StringBuilder("'use strict';\n");
        StringBuilder html = new StringBuilder(
            "<div class='header'>Wallet Administration</div>" +

            "<div style='display:flex;justify-content:center;margin-top:15pt'>" +
              "<div class='comment'>" +
                "The &quot;Wallet&quot; is a central part of FWP since it holds all " +
                "related payment cards" +
              "</div>" +
            "</div>");

        html.append(EnrollServlet.hasWalletCookie(request) ?

            "<form name='shoot' method='POST' action='walletadmin'></form>" +
            "<div style='display:flex;justify-content:center'>" +
              "<div class='stdbtn' onclick=\"document.forms.shoot.submit()\">" +
                "Delete Cards!" +
              "</div>" +
            "</div>"
                                          :
            "<div class='important'>" +
              "You currently have no payment cards" +
            "</div>");

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
            StringBuilder js = new StringBuilder("'use strict';\n");
                StringBuilder html = new StringBuilder(
                        "<form name='shoot' method='POST' action='hash'>" +
                        "<div class='header'>Payment Cards Deleted</div>" +
                        "<div style='display:flex;justify-content:center;margin-top:15pt'>")
                    .append("Thank you testing.  We hope that you liked it!")
                    .append(
                        "</div>" +
                        "</form>");
                js.append("// hi\n");
                Cookie walletCookie = new Cookie(EnrollServlet.WALLET_COOKIE,"");
                walletCookie.setMaxAge(0);
                response.addCookie(walletCookie);
                HTML.standardPage(response, 
                                 js.toString(),
                                 html);
        } catch (Exception e) {
            HTML.errorPage(response, e);
        }
    }
}
