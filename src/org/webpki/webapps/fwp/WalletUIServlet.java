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
import org.webpki.json.JSONArrayWriter;
import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONOutputFormats;
import org.webpki.json.JSONParser;

/**
 * This is the wallet UI (which is yet missing)
 *
 */
public class WalletUIServlet extends HttpServlet {
    
    static Logger logger = Logger.getLogger(WalletUIServlet.class.getName());

    private static final long serialVersionUID = 1L;
    
    // DIV elements to turn on and turn off.
    private static final String WAITING_ID     = "wait";
    private static final String ACTIVATE_ID    = "activate";

    private StringBuilder cardSelector(JSONArrayReader cards) throws IOException {
        StringBuilder selector = new StringBuilder(
            "<div style='display:flex;align-items:center;flex-direction:column;margin-top:15pt'>" +
              "<div>");
        int i = 0;
        while (cards.hasMore()) {
            selector.append("<div onclick='selectCard(")
                    .append(i++)
                    .append(")'>")
                    .append(cards.getObject().getString(WalletCore.ACCOUNT_ID))
                    .append("</div>");
        }
        return selector.append("</div></div>");
    }

    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {
        request.setCharacterEncoding("utf-8");
        String walletInternal = request.getParameter(WalletCore.WALLET_INTERNAL);
        if (walletInternal == null) {
            WalletCore.failed("Missing wallet request");
        }
        JSONObjectReader walletInternalJson = JSONParser.parse(walletInternal);
 
        // What the Merchant wants...
        JSONObjectReader paymentRequest =
                walletInternalJson.getObject(WalletCore.PAYMENT_REQUEST);
        
        StringBuilder html = new StringBuilder(
            "<form name='shoot' method='POST' action='ad'>" +
            "<input type='hidden' id='" + WalletCore.WALLET_INTERNAL + "' name='" +
                                          WalletCore.WALLET_INTERNAL + "'/>" +
            "</form>" +

            "<div class='header'>Wallet UI</div>" +

            "<div style='display:flex;justify-content:center;margin-top:15pt'>" +
              "<div class='comment'>")
        .append(ADServlet.sectionReference("seq-2"))
        .append(
              ": Select a payment card.  Only the cards matching the " +
              "the list of supported methods supplied by the " +
              "<span class='actor'>Merchant</span> will be shown." +
             "</div>" +
            "</div>");
             
        html.append(cardSelector(walletInternalJson.getArray(WalletCore.MATCHING_CARDS)))
        .append(
  
            "<div style='display:flex;justify-content:center'>" +
              "<img id='" + WAITING_ID + "' src='images/waiting.gif' " +
                  "style='padding-top:2em;display:none' alt='waiting'/>" +
            "</div>" +

            "<div style='display:flex;justify-content:center'>" +
              "<div style='display:none' id='" + ACTIVATE_ID + "' class='stdbtn' onclick=\"doContinue()\">" +
                "Continue..." +
              "</div>" +
            "</div>");
        

        String js = new StringBuilder(

            WalletCore.GO_HOME_JAVASCRIPT +
            
            "let cards = ")
        .append(new JSONArrayWriter(walletInternalJson.getArray(WalletCore.MATCHING_CARDS))
                .serializeToString(JSONOutputFormats.PRETTY_JS_NATIVE))
        .append(
            ";\n" +
            "let selectedCard;\n" +
                    
            "function selectCard(index) {\n" +
            "  if (selectedCard != cards[index]) {\n" +
            "    console.log('new card:' + index);\n" +
            "    selectedCard = cards[index];\n" +
            "  }\n" +
            "}\n" +
            
            "window.addEventListener('load', function(event) {\n" +
            "  selectCard(0);\n" +
            "  document.getElementById('" + ACTIVATE_ID + "').style.display = 'block';\n" +
            "});\n" +
            
            "function doContinue() {\n" +
            "  document.getElementById('" + ACTIVATE_ID + "').style.display = 'none';\n" +
            "  document.getElementById('" + WAITING_ID + "').style.display = 'block';\n" +
            "  document.getElementById('" + WalletCore.WALLET_INTERNAL + 
              "').value = JSON.stringify({" + WalletCore.PAYMENT_REQUEST + ": ")
        .append(paymentRequest.serializeToString(JSONOutputFormats.PRETTY_JS_NATIVE))
        .append(", " + WalletCore.SELECTED_CARD + ": selectedCard});\n" +
            "  setTimeout(function() {\n" +
            "    document.forms.shoot.submit();\n" +
            "  }, 500);\n" +
            "}\n").toString();

        HTML.standardPage(response, Actors.FWP, js, html); 
    }
}
