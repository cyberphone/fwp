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
        StringBuilder html = new StringBuilder(
            "<form name='shoot' method='POST' action='pr'>" +
        
            "<input type='hidden' id='" + FWPWalletCore.WALLET_REQUEST + 
                "' name='" + FWPWalletCore.WALLET_REQUEST + "'/>" +

            "<div class='header'>Checkout Time!</div>" +

            "<div style='display:flex;justify-content:center;margin-top:15pt'>" +
              "<div class='comment'>" +
                  "This is a temporary arrangement where you just pay &#x20ac;&#x2009;435." +
                  "<div style='margin-top:0.4em'>It will later be replaced by a " +
                  "simple merchant application.</div>" +
              "</div>" +
            "</div>" +

            "<div class='header' style='margin:1em 0'>Select Payment Method</div>" +
            
            "<div id='" + NOTIFIER + "' class='toasting'>This demo only supports FWP...</div>" +
            
            "<div style='display:flex;align-items:center;flex-direction:column'>" +
              "<img src='images/fwpminiplus-pay.svg' class='payimage' " +
                 "onclick='doPay()' alt='image'/>" +
              "<img src='images/paypal-pay.svg' class='payimage' " +
                  "onclick='unsupported(this)' style='margin:1em 0' alt='image'/>" +
              "<img src='images/legacy-visamc-pay.svg' class='payimage' " + 
                 "onclick='unsupported(this)' alt='image'/>" +
            "</div>" +
             
            "<div style='display:flex;justify-content:center;margin-top:15pt'>" +
              "<div style='max-width:40em'>" +
                "Note that FIDO Web Pay follows the FIDO paradigm by being " +
                "<i>payment system neutral</i>. " +
                "This also makes the user experience <i>identical</i> when performing a " +
                "SEPA instant payment or using an international card network like VISA." +
              "</div>" +
            "</div>" +
            
            "</form>");

        String js = new StringBuilder(
            "const paymentRequest = ")
        .append(FWPService.samplePaymentRequest.serializeAsJSON(JSONOutputFormats.PRETTY_JS_NATIVE))
        .append(
            ";\n" +
        
            "const paymentMethods = [\n" +
            "  'https://bankdirect.com',\n" +
            "  'https://supercard.com'\n" +
            "]\n" +
/*
            "const accountData = {" +
            " id: 'FR7630002111110020050014382',\n" +
            " pm: 'https://bank<table>\\'\\u20acdirect.com',\n" +
            " sn: '0057162932',\n" +
            " ii: 'https://mybank.fr/payment'\n" +
            "};\n" +
*/            
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
                "').value = JSON.stringify({" + 
                FWPWalletCore.PAYMENT_REQUEST + ": paymentRequest, " +
                FWPWalletCore.PAYMENT_METHODS + ": paymentMethods});\n" +
            "  document.forms.shoot.submit();\n" +
            "}\n").toString();
        HTML.standardPage(response, js, html);
    }
}
