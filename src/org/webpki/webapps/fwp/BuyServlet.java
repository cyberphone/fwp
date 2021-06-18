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

import org.webpki.json.JSONOutputFormats;

/**
 * This is a temporary payment application.
 *
 */
public class BuyServlet extends HttpServlet {
    
    static Logger logger = Logger.getLogger(BuyServlet.class.getName());

    private static final long serialVersionUID = 1L;
    
    private static final String NOTIFIER = "notifier";
    
   
    public void doGet(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {
        if (FWPWalletCore.getWalletCookie(request) == null) {
            HTML.standardPage(response, null, new StringBuilder(
                "<div class='important'>User ID is missing, have you enrolled?</div>"));
            return;
        }

        StringBuilder html = new StringBuilder(
            "<form name='shoot' method='POST' action='ad'>" +
        
            "<input type='hidden' id='" + FWPWalletCore.WALLET_REQUEST + 
                "' name='" + FWPWalletCore.WALLET_REQUEST + "'/>" +

            "<div class='header'>Checkout Time!</div>" +

            "<div style='display:flex;justify-content:center;margin-top:15pt'>" +
              "<div class='comment'>" +
                  "This is just a temporary arrangement where you pay 435 EUR." +
                  "<div style='margin-top:0.4em'>It will later be replaced by a " +
                  "merchant application as well as the FWP wallet UI.</div>" +
              "</div>" +
            "</div>" +

            "<div class='header' style='margin:1em 0'>Select Payment Method</div>" +
            
            "<div id='" + NOTIFIER + "' class='toasting'>This demo only supports FWP...</div>" +
            
            "<div style='display:flex;justify-content:center'>" +
              "<table>" +
                "<tr><td><img src='images/fwpminiplus-pay.svg' class='payimage' " +
                  "onclick='doPay()'/></td></tr>" +
                "<tr><td><img src='images/paypal-pay.svg' class='payimage' " +
                  "onclick='unsupported(this)' style='margin:0.8em 0'/></td></tr>" +
                "<tr><td><img src='images/legacy-visamc-pay.svg' class='payimage' " + 
                  "onclick='unsupported(this)'/></td></tr>" +
             "</table>" +
            "</div>" +
            
            "</form>");

        String js = new StringBuilder(
            "const paymentRequest = ")
        .append(FWPService.samplePaymentRequest.serializeAsJSON(JSONOutputFormats.PRETTY_JS_NATIVE))
        .append(
            ";\n" +

            "const accountData = {" +
            " id: 'FR7630002111110020050014382',\n" +
            " pm: 'https://bankdirect.com',\n" +
            " sn: '0057162932',\n" +
            " ii: 'https://mybank.fr/payment'\n" +
            "};\n" +
            
            "function unsupported(target) {\n" +
            "  let notifier = document.getElementById('" + NOTIFIER + "');\n" +
            "  notifier.style.top = (target.getBoundingClientRect().top + window.scrollY - " +
                "notifier.offsetHeight) + 'px';\n" +
            "  notifier.style.left = ((window.innerWidth - notifier.offsetWidth) / 2) + 'px';\n" +
            "  notifier.style.visibility = 'visible';\n" +
            "  setTimeout(function() {\n" +
            "    notifier.style.visibility = 'hidden';\n" +
            "  }, 1000);\n" +
            "}\n\n" +

            "function doPay() {\n" +
            "  document.getElementById('" + FWPWalletCore.WALLET_REQUEST + 
                "').value = JSON.stringify({pr: paymentRequest, ad: accountData});\n" +
            "  document.forms.shoot.submit();\n" +
            "}\n").toString();
        HTML.standardPage(response, js, html);
    }
}
