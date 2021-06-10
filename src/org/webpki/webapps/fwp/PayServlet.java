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

import java.sql.Connection;

import java.util.Base64;

import java.util.logging.Logger;

import javax.servlet.ServletException;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.webpki.cbor.CBORMap;
import org.webpki.cbor.CBORObject;

import org.webpki.fwp.FWPCrypto;
import org.webpki.json.JSONOutputFormats;

/**
 * This is a temporary payment application.
 *
 */
public class PayServlet extends HttpServlet {
    
    static Logger logger = Logger.getLogger(PayServlet.class.getName());

    private static final long serialVersionUID = 1L;
    
    
    // DIV elements to turn on and turn off.
    private static final String WAITING_ID     = "wait";
    private static final String FAILED_ID      = "fail";
    private static final String ACTIVATE_ID    = "activate";

    
    public void doGet(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {
        StringBuilder html = new StringBuilder(
            "<form name='shoot' method='POST' action='pay'>" +
        
            "<input type='hidden' id='" + FWPCommon.FWP_ASSERTION + 
                "' name='" + FWPCommon.FWP_ASSERTION + "'/>" +

            "<div class='header'>Checkout Time!</div>" +

            "<div style='display:flex;justify-content:center;margin-top:15pt'>" +
              "<div class='comment'>" +
                  "This is just a temporary arrangement where you pay 140 EUR." +
              "</div>" +
            "</div>" +
            
            "<div style='display:flex;justify-content:center'>" +
              "<img id='" + WAITING_ID + "' src='images/waiting.gif' " +
                  "style='padding-top:2em;display:none' alt='waiting'/>" +
            "</div>" +

            "<div id='" + FAILED_ID + "' class='errorText'></div>" +

            "<div style='display:flex;justify-content:center'>" +
              "<div id='" + ACTIVATE_ID + "' class='stdbtn' onclick=\"doPay()\">" +
                "Pay using FWP" +
              "</div>" +
            "</div>" +
            "</form>");

        String js = new StringBuilder(
            "'use strict';\n" +
        
            "const paymentRequest = ")
        .append(FWPService.samplePaymentRequest.serializeToString(JSONOutputFormats.PRETTY_JS_NATIVE))
        .append(
            ";\n" +
            
            "const serviceUrl = 'fidopay';\n" +

            FWPCommon.FWP_JAVASCRIPT +

            "async function doPay() {\n" +
            "  try {\n" +
            "    document.getElementById('" + ACTIVATE_ID + "').style.display = 'none';\n" +
            "    document.getElementById('" + WAITING_ID + "').style.display = 'block';\n" +
            "    const initPhase = await exchangeJSON({'" +
              FWPCommon.PAYMENT_REQUEST + "': paymentRequest},'" + FWPCommon.INIT_PHASE + "');\n" +

            "    const options = {\n" +
            "      challenge: b64urlToU8arr(initPhase." + FWPCrypto.CHALLENGE + "),\n" +

            "      allowCredentials: [{type: 'public-key', " +
                       "id: b64urlToU8arr(initPhase." + FWPCrypto.CREDENTIAL_ID + ")}],\n" +

            "      userVerification: 'preferred',\n" +

            "      timeout: 120000\n" +
            "    };\n" +
            
//            "    console.log(options);\n" +
            "    const result = await navigator.credentials.get({ publicKey: options });\n" +
//            "    console.log(result);\n" +
            "    const finalizePhase = await exchangeJSON({" + 

                         FWPCrypto.AUTHENTICATOR_DATA_JSON + 
                         ":arrBufToB64url(result.response.authenticatorData)," +

                         FWPCrypto.SIGNATURE_JSON + 
                         ":arrBufToB64url(result.response.signature)," +

                         FWPCrypto.CLIENT_DATA_JSON + 
                         ":arrBufToB64url(result.response.clientDataJSON)},'" +

                         FWPCommon.FINALIZE_PHASE + "');\n" +

            "    document.getElementById('" + FWPCommon.FWP_ASSERTION + 
                "').value = finalizePhase." + FWPCommon.FWP_ASSERTION + ";\n" +
            "    document.forms.shoot.submit();\n" +

            // Errors are effectively aborting so a single try-catch does the trick.
            "  } catch (error) {\n" +
            "    let message = 'Fail: ' + error;\n" +
            "    console.log(message);\n" +
            "    document.getElementById('" + WAITING_ID + "').style.display = 'none';\n" +
            "    let e = document.getElementById('" + FAILED_ID + "');\n" +
            "    e.textContent = message;\n" +
            "    e.style.display = 'block';\n" +
            "  }\n" +

            "}\n").toString();
        HTML.standardPage(response, js, html);
    }
    
    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {
        try {
            String fwpAssertionB64U = request.getParameter(FWPCommon.FWP_ASSERTION);
            if (fwpAssertionB64U == null) {
                FWPCommon.failed("FWP assertion missing");
            }

            String userId = FWPCommon.getWalletCookie(request);
            if (userId == null) {
                FWPCommon.failed("User ID missing, have you enrolled?");
            }

            CBORMap fwpAssertion = 
                    CBORObject.decode(
                            Base64.getUrlDecoder().decode(fwpAssertionB64U)).getMap();
            
//            byte[] publicKey = FWPCrypto.validateFwpAssertion(fwpAssertion);
  byte[] publicKey = null;          
            // Succeeded.  Is the key one of "ours"?
            try (Connection connection = FWPService.jdbcDataSource.getConnection();) {
                DataBaseOperations.authenticate(userId, publicKey, connection);
            }
            
            StringBuilder html = new StringBuilder(
                    "<div class='header'>Signed Authorization Created</div>" +
            
                    "<div style='display:flex;justify-content:center;margin-top:15pt'>" +
                      "<div class='comment'>" +
                         "The following is what the browser (FWP implementation) generated internally." +
                      "</div>" +
                    "</div>" +

                    "<div style='display:flex;align-items:center;flex-direction:column;margin-top:15pt'>" +
                        "<div class='ctbl'>")
                .append(fwpAssertion.toString().replace("\n", "<br>").replace(" ", "&nbsp;"))
                .append("</div>" +
                    "</div>");
            
            HTML.standardPage(response, FWPCommon.GO_HOME_JAVASCRIPT, html);
        } catch (Exception e) {
            HTML.errorPage(response, e);
        }
    }
}
