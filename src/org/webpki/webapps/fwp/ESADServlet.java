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

import java.util.Base64;

import java.util.logging.Logger;

import javax.servlet.ServletException;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.webpki.cbor.CBORAsymKeyEncrypter;
import org.webpki.cbor.CBORMap;

/**
 * Creates and shows the encrypted SAD object (ESAD).
 *
 */
public class ESADServlet extends HttpServlet {
    
    static Logger logger = Logger.getLogger(ESADServlet.class.getName());

    private static final long serialVersionUID = 1L;
    
    // DIV elements to turn on and turn off.
    private static final String WAITING_ID     = "wait";
    private static final String ACTIVATE_ID    = "activate";
    
    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {
        request.setCharacterEncoding("utf-8");
        try {
            String signedAuthorizationDataB64U = request.getParameter(FWPWalletCore.FWP_SAD);
            if (signedAuthorizationDataB64U == null) {
                FWPWalletCore.failed("FWP assertion missing");
            }
            String walletInternal = request.getParameter(FWPWalletCore.WALLET_INTERNAL);
            if (walletInternal == null) {
                FWPWalletCore.failed("Missing wallet data");
                return;
            }            
            CBORMap encrypted = 
                    new CBORAsymKeyEncrypter(FWPService.issuerEncryptionKey.getPublic(),
                                             FWPService.issuerKeyEncryptionAlgorithm,
                                             FWPService.issuerContentEncryptionAlgorithm)
                .setKeyId(FWPService.issuerKeyId).encrypt(
                        Base64.getUrlDecoder().decode(signedAuthorizationDataB64U));

            StringBuilder html = new StringBuilder(
                "<form name='shoot' method='POST' action='finalizeassertion'>" +
                "<input type='hidden' name='" + FWPWalletCore.FWP_ESAD + 
                "' value='")
            .append(Base64.getUrlEncoder().withoutPadding().encodeToString(encrypted.encode()))
            .append(
                "'/>" +
                "<input type='hidden' name='" + FWPWalletCore.WALLET_INTERNAL + "' value='")
            .append(HTML.encode(walletInternal, false))
            .append(
                "'/>" +
                "</form>" +

                "<div class='header'>Encrypted SAD =&gt; ESAD</div>" +
        
                "<div style='display:flex;justify-content:center;margin-top:15pt'>" +
                  "<div class='comment'>")
            .append(ADServlet.sectionReference("seq-4.4"))
            .append(
                  "The authorization data has now been signed and encrypted, " +
                  "the latter using an <i>issuer-specific key</i>." +
                  "<div style='margin-top:0.4em'>However, payment backend processing needs some data " +
                  "in clear in order to perform its work.</div>" +
                  "</div>" +
                "</div>" +

                "<div style='display:flex;justify-content:center'>" +
                  "<img id='" + WAITING_ID + "' src='images/waiting.gif' " +
                      "style='padding-top:2em;display:none' alt='waiting'/>" +
                "</div>" +     
                
                "<div style='display:flex;justify-content:center'>" +
                  "<div id='" + ACTIVATE_ID + "' class='stdbtn' onclick=\"doFinalize()\">" +
                    "<i>Finalize</i> Assertion" +
                  "</div>" +
                "</div>" +

                "<div class='staticbox'>")
            .append(HTML.encode(encrypted.toString(), true))
            .append(
                "</div>");
 
            String js = new StringBuilder(

                FWPWalletCore.GO_HOME_JAVASCRIPT +
                
                "function doFinalize() {\n" +
                "  document.getElementById('" + ACTIVATE_ID + "').style.display = 'none';\n" +
                "  document.getElementById('" + WAITING_ID + "').style.display = 'block';\n" +
                "  setTimeout(function() {\n" +
                "    document.forms.shoot.submit();\n" +
                "  }, 1000);\n" +
                "}\n").toString();

                HTML.standardPage(response, Actors.FWP, js, html);
        } catch (Exception e) {
            HTML.errorPage(response, e);
        }
    }
}
