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

import org.webpki.json.JSONArrayReader;
import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONObjectWriter;
import org.webpki.json.JSONOutputFormats;
import org.webpki.json.JSONParser;

/**
 * This is the wallet UI (which is yet missing)
 *
 */
public class PaymentRequestServlet extends HttpServlet {
    
    static Logger logger = Logger.getLogger(PaymentRequestServlet.class.getName());

    private static final long serialVersionUID = 1L;
    
    // DIV elements to turn on and turn off.
    private static final String WAITING_ID     = "wait";
    private static final String FAILED_ID      = "fail";
    private static final String ACTIVATE_ID    = "activate";


    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {
        request.setCharacterEncoding("utf-8");
        String walletRequest = request.getParameter(FWPWalletCore.WALLET_REQUEST);
        if (walletRequest == null) {
            FWPWalletCore.failed("Missing wallet request");
        }
        logger.info(walletRequest);
        JSONObjectReader walletRequestJson = JSONParser.parse(walletRequest);
        try {
            // Get the enrolled user.
            String userId = FWPWalletCore.getWalletCookie(request);
            if (userId == null) {
                response.sendRedirect("walletadmin");
                return;
            }

            // 
            JSONArrayReader paymentMethods = 
                    walletRequestJson.getArray(FWPWalletCore.PAYMENT_METHODS);
            JSONObjectReader paymentRequest =
                    walletRequestJson.getObject(FWPWalletCore.PAYMENT_REQUEST);
            JSONObjectWriter walletInternal = new JSONObjectWriter()
                    .setObject(FWPWalletCore.PAYMENT_REQUEST, paymentRequest)
                    .setObject(FWPWalletCore.ACCOUNT_DATA, new JSONObjectWriter()
                            .setString(FWPWalletCore.ACCOUNT_ID, "FR7630002111110020050014382")
                            .setString(FWPWalletCore.PAYMENT_METHOD, paymentMethods.getString())
                            .setString(FWPWalletCore.SERIAL_NUMBER, "0057162932")
                            .setString(FWPWalletCore.ISSUER_ID, "https://mybank.fr/payment"));
             
            StringBuilder html = new StringBuilder(
                "<form name='shoot' method='POST' action='ad'>" +
                "<input type='hidden' id='" + FWPWalletCore.FWP_SAD + 
                    "' name='" + FWPWalletCore.FWP_SAD + "'/>" +
                "<input type='hidden' name='" + FWPWalletCore.WALLET_INTERNAL + "' value='")
            .append(HTML.encode(walletInternal.serializeToString(JSONOutputFormats.NORMALIZED),
                                false))
            .append(
                "'/>" +
                "</form>" +

                "<div class='header'>Payment Request</div>" +

                "<div style='display:flex;justify-content:center;margin-top:15pt'>" +
                  "<div class='comment'>")
            .append(ADServlet.sectionReference("seq-2"))
            .append(
                  "This is what the Merchant's call to the W3C PaymentRequest API " +
                  "boils down to.  The wallet UI has not yet been written so " +
                  "we just go for the first payment method that matches any of the " +
                  "ones specified by the Merchant." +
                 "</div>" +
                "</div>" +
                
                "<div style='display:flex;justify-content:center'>" +
                  "<img id='" + WAITING_ID + "' src='images/waiting.gif' " +
                      "style='padding-top:2em;display:none' alt='waiting'/>" +
                "</div>" +

                "<div id='" + FAILED_ID + "' class='errorText'></div>" +

                "<div style='display:flex;justify-content:center'>" +
                  "<div id='" + ACTIVATE_ID + "' class='stdbtn' onclick=\"doContinue()\">" +
                    "Continue..." +
                  "</div>" +
                "</div>" +

                "<div class='staticbox'>")
            .append(HTML.encode(walletRequestJson.toString(), true))
            .append(
                "</div>");

            String js = new StringBuilder(

                    FWPWalletCore.GO_HOME_JAVASCRIPT +
                    
                    "function doContinue() {\n" +
                    "  document.getElementById('" + ACTIVATE_ID + "').style.display = 'none';\n" +
                    "  document.getElementById('" + WAITING_ID + "').style.display = 'block';\n" +
                    "  setTimeout(function() {\n" +
                    "    document.forms.shoot.submit();\n" +
                    "  }, 1000);\n" +
                    "}\n").toString();

            HTML.standardPage(response, js, html); 
        } catch (Exception e) {
            HTML.errorPage(response, e);
        }
    }
}
