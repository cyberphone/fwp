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

import java.util.GregorianCalendar;

import java.util.logging.Logger;

import javax.servlet.ServletException;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.webpki.fwp.FWPJsonAssertion;
import org.webpki.fwp.FWPPaymentRequest;
import org.webpki.fwp.PSPRequest;

import org.webpki.json.JSONParser;

/**
 * Return to merchant after successful FWP invocation.
 *
 */
public class MerchantServlet extends HttpServlet {
    
    static Logger logger = Logger.getLogger(MerchantServlet.class.getName());

    private static final long serialVersionUID = 1L;
    
    // DIV elements to turn on and turn off.
    private static final String WAITING_ID     = "wait";
    private static final String ACTIVATE_ID    = "activate";
    
    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {
        request.setCharacterEncoding("utf-8");
        String fwpAssertion = request.getParameter(WalletCore.FWP_ASSERTION);
        if (fwpAssertion == null) {
            WalletCore.failed("Missing FWP assertion");
            return;
        }
        String paymentRequest = request.getParameter(WalletCore.PAYMENT_REQUEST);
        if (paymentRequest == null) {
            WalletCore.failed("Missing payment request");
            return;
        }    
        FWPJsonAssertion fwpJsonAssertion = 
                new FWPJsonAssertion(JSONParser.parse(fwpAssertion));
        FWPPaymentRequest fwpPaymentRequest = 
                new FWPPaymentRequest(JSONParser.parse(paymentRequest));
        PSPRequest pspRequest = new PSPRequest(fwpPaymentRequest,
                                               fwpJsonAssertion,
                                               "DE89370400440532013000", 
                                               request.getRemoteAddr(), 
                                               new GregorianCalendar());
        StringBuilder html = new StringBuilder(
            "<form name='shoot' method='POST' action='pspreq'>" +
            "<input type='hidden' name='" + PSPServlet.PSP_REQUEST +
            "' value='")
        .append(HTML.encode(pspRequest.serialize(), false))
        .append(
            "'/>" +
            "</form>" +

            "<div class='header'>Return to Merchant</div>" +

            "<div style='display:flex;justify-content:center;margin-top:15pt'>" +
              "<div class='comment'>")
        .append(ADServlet.sectionReference("seq-6"))
        .append(
              ": The <span class='actor'>Merchant</span> checkout software has now " +
              "returned the authorization response " +
              "from the <span class='actor'>Wallet</span>.  The next step is taking " +
              "the authorization (together with other data), " +
              "to a suitable Payment System Provider " +
              "(<span class='actor'>PSP</span>) " +
              "for fulfillment." +
              "<div style='margin-top:0.4em'>Below is a <i>non-normative</i> " +
              "sample <span class='actor'>PSP</span> message.</div>" +
              "<div style='margin-top:0.4em'>Note: &quot;backend&quot; processing " +
              "is <i>invisible</i> for the <span class='actor'>User</span>; " +
              "he/she stays in the <span class='actor'>Merchant</span> context " +
              "throughout the payment journey!</div>" +
              "</div>" +
            "</div>" +
              
            "<div style='display:flex;justify-content:center'>" +
              "<img id='" + WAITING_ID + "' src='images/waiting.gif' " +
                 "style='padding-top:2em;display:none' alt='waiting'/>" +
            "</div>" +  
              
            "<div style='display:flex;justify-content:center'>" +
              "<div id='" + ACTIVATE_ID + "' class='stdbtn' onclick=\"doReturn()\">" +
                  "Send Request to PSP" +
              "</div>" +
            "</div>" +
        
            "<div class='staticbox'>")
        .append(HTML.encode(pspRequest.toString(), true))
        .append(
            "</div>");
        String js = new StringBuilder(
        
        WalletCore.GO_HOME_JAVASCRIPT +
  
        "function doReturn() {\n" +
        "  document.getElementById('" + ACTIVATE_ID + "').style.display = 'none';\n" +
        "  document.getElementById('" + WAITING_ID + "').style.display = 'block';\n" +
        "  setTimeout(function() {\n" +
        "    document.forms.shoot.submit();\n" +
        "  }, 500);\n" +
        "}\n").toString();
        
        HTML.standardPage(response, Actors.MERCHANT, js, html);
    }
}
