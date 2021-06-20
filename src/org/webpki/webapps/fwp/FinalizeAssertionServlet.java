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

import org.webpki.fwp.FWPJsonAssertion;

import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONOutputFormats;
import org.webpki.json.JSONParser;

/**
 * Creates and shows the finalized FWP assertion.
 *
 */
public class FinalizeAssertionServlet extends HttpServlet {
    
    static Logger logger = Logger.getLogger(FinalizeAssertionServlet.class.getName());

    private static final long serialVersionUID = 1L;
    
    // DIV elements to turn on and turn off.
    private static final String WAITING_ID     = "wait";
    private static final String ACTIVATE_ID    = "activate";
    
    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {
        request.setCharacterEncoding("utf-8");
        String encryptedSignedAuthorizationB64U = request.getParameter(FWPWalletCore.FWP_ESAD);
        if (encryptedSignedAuthorizationB64U == null) {
            FWPWalletCore.failed("Missing encrypted signed authorization data");
            return;
        }
        String walletInternal = request.getParameter(FWPWalletCore.WALLET_INTERNAL);
        if (walletInternal == null) {
            FWPWalletCore.failed("Missing wallet data");
            return;
        }     
        JSONObjectReader accountData = 
                JSONParser.parse(walletInternal).getObject(FWPWalletCore.ACCOUNT_DATA);
        FWPJsonAssertion fwpAssertion =
                new FWPJsonAssertion(accountData.getString(FWPWalletCore.PAYMENT_METHOD),
                                     accountData.getString(FWPWalletCore.ISSUER_ID),
                                     Base64.getUrlDecoder().decode(
                                             encryptedSignedAuthorizationB64U));
        StringBuilder html = new StringBuilder(
            "<form name='shoot' method='POST' action='merchant'>" +
            "<input type='hidden' name='" + FWPWalletCore.FWP_ASSERTION +
            "' value='")
        .append(HTML.encode(fwpAssertion.serialize(), false))
        .append(
            "'/>" +
            "<input type='hidden' name='" + FWPWalletCore.PAYMENT_REQUEST + "' value='")
        .append(HTML.encode(JSONParser.parse(walletInternal).getObject(
                FWPWalletCore.PAYMENT_REQUEST).serializeToString(JSONOutputFormats.NORMALIZED),
                            false))
        .append(
            "'/>" +
            "</form>" +

            "<div class='header'>Finally, the FWP Assertion!</div>" +

            "<div style='display:flex;justify-content:center;margin-top:15pt'>" +
              "<div class='comment'>")
        .append(ADServlet.sectionReference("seq-4.5"))
        .append(
                  "The following data represents the completed FWP assertion." +
                  "<div style='margin-top:0.4em'>To simplify usage in browsers and " +
                  "payment processors, FWP assertions are provided as JSON objects. "+
                  "Only verifiers need to deal with low-level CBOR processing.</div>" +
              "</div>" +
            "</div>" +

            "<div style='display:flex;justify-content:center'>" +
              "<img id='" + WAITING_ID + "' src='images/waiting.gif' " +
                "style='padding-top:2em;display:none' alt='waiting'/>" +
            "</div>" +  
            
            "<div style='display:flex;justify-content:center'>" +
              "<div id='" + ACTIVATE_ID + "' class='stdbtn' onclick=\"doReturn()\">" +
                "Return FWP Assertion to Merchant" +
              "</div>" +
            "</div>" +

            "<div class='staticbox'>")
        .append(HTML.encode(fwpAssertion.toString(), true))
        .append(
            "</div>");
        String js = new StringBuilder(

            FWPWalletCore.GO_HOME_JAVASCRIPT +
            
            "function doReturn() {\n" +
            "  document.getElementById('" + ACTIVATE_ID + "').style.display = 'none';\n" +
            "  document.getElementById('" + WAITING_ID + "').style.display = 'block';\n" +
            "  setTimeout(function() {\n" +
            "    document.forms.shoot.submit();\n" +
            "  }, 1000);\n" +
            "}\n").toString();

        HTML.standardPage(response, js, html);
    }
}
