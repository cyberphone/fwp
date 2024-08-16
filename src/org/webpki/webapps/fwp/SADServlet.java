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

import java.util.logging.Logger;

import javax.servlet.ServletException;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.webpki.cbor.CBORDecoder;

/**
 * Receives and shows the Signed Authorization Data (SAD).
 *
 */
public class SADServlet extends HttpServlet {
    
    static Logger logger = Logger.getLogger(SADServlet.class.getName());

    private static final long serialVersionUID = 1L;
    
    // DIV elements to turn on and turn off.
    private static final String WAITING_ID     = "wait";
    private static final String ACTIVATE_ID    = "activate";
    
    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {
        request.setCharacterEncoding("utf-8");
        String signedAuthorizationB64U = request.getParameter(WalletCore.FWP_SAD);
        if (signedAuthorizationB64U == null) {
            WalletCore.failed("Missing signed authorization data");
            return;
        }
        String walletInternal = request.getParameter(WalletCore.WALLET_INTERNAL);
        if (walletInternal == null) {
            WalletCore.failed("Missing wallet data");
            return;
        }
        logger.info("Successful authorization by: " + WalletCore.getWalletCookie(request));
        StringBuilder html = new StringBuilder(
            "<form name='shoot' method='POST' action='esad'>" +
            "<input type='hidden' name='" + WalletCore.FWP_SAD + "' value='")
        .append(signedAuthorizationB64U)
        .append(
            "'/>" +
            "<input type='hidden' name='" + WalletCore.WALLET_INTERNAL+ "' value='")
        .append(HTML.encode(walletInternal, false))
        .append(
            "'/>" +
            "</form>" +

            "<div class='header'>Signed Authorization Data (SAD)</div>" +

            "<div style='display:flex;justify-content:center;margin-top:15pt'>" +
              "<div class='comment'>")
        .append(ADServlet.sectionReference("seq-4.3"))
        .append(
              ": The FIDO signature has now been added. " +
              "<div style='margin-top:0.4em'>&#x1f449; Note that the Web emulator " +
              "for compatibility with browsers uses a slightly different signature " +
              "scheme than the specification, " +
              "requiring <code>clientDataJSON</code> as well &#x1f448;</div>" +
              "<div style='margin-top:0.4em'>Since FWP is a <i>privacy-centric scheme</i>, " +
              "the authorization data is not yet ready for release.</div>" +
              "</div>" +
            "</div>" +

            "<div style='display:flex;justify-content:center'>" +
              "<img id='" + WAITING_ID + "' src='images/waiting.gif' " +
                  "style='padding-top:2em;display:none' alt='waiting'/>" +
            "</div>" +            
            
            "<div style='display:flex;justify-content:center'>" +
              "<div id='" + ACTIVATE_ID + "' class='stdbtn' onclick=\"doEncrypt()\">" +
              "<i>Encrypt</i> Authorization" +
              "</div>" +
            "</div>" +

            "<div class='staticbox'>")
        .append(HTML.encode(CBORDecoder.decode(
                    ApplicationService.base64UrlDecode(signedAuthorizationB64U)).toString(), true))
        .append(
            "</div>");
        
        String js = new StringBuilder(

            WalletCore.GO_HOME_JAVASCRIPT +
            
            "function doEncrypt() {\n" +
            "  document.getElementById('" + ACTIVATE_ID + "').style.display = 'none';\n" +
            "  document.getElementById('" + WAITING_ID + "').style.display = 'block';\n" +
            "  setTimeout(function() {\n" +
            "    document.forms.shoot.submit();\n" +
            "  }, 500);\n" +
            "}\n").toString();

        HTML.standardPage(response, Actors.FWP, js, html);
    }
}
