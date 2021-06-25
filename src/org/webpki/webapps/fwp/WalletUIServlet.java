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

import org.webpki.fwp.FWPPaymentRequest;

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
              ": Select a payment card and authorize the payment request. " +
              "Only the cards in the " +
              "<span class='actor'>Wallet</span> matching the " +
              "list of supported methods supplied by the " +
              "<span class='actor'>Merchant</span> will be shown." +
              "<div style='margin-top:0.4em'>You change card by <i>swiping</i> " +
              "the card image to the left or right.</div>" +
             "</div>" +
            "</div>" +

            "<div style='display:flex;align-items:center;flex-direction:column;margin-top:1.5em'>" +
            "<div style='display:flex;align-items:center;flex-direction:column;border-width:1px;border-style:solid;border-color:grey;padding:1em'>" +
            "<img id='card' src='' style='width:30em;max-width:80%'/>" +
            "<table style='margin-top:1em'>" +
            "<tr><th>Payee</th><td>")
        .append(paymentRequest.getString(FWPPaymentRequest.JSON_PR_PAYEE_NAME))
        .append(
            "</td></tr>" +
            "<tr><th>Total</th><td>&#x20ac; ")
        .append(paymentRequest.getString(FWPPaymentRequest.JSON_PR_AMOUNT))
        .append(
            "</td></tr>" +
            "</table>" +
            
            "<img id='" + WAITING_ID + "' src='images/waiting.gif' " +
                  "style='padding-top:1.5em;display:none' alt='waiting'/>" +

            "<div style='display:none' id='" + ACTIVATE_ID + "' class='stdbtn' onclick=\"doContinue()\">" +
                "Continue..." +
            "</div>" +
                
            "</div>" +
            "</div>");
        

        String js = new StringBuilder(

            WalletCore.GO_HOME_JAVASCRIPT +
            
            "let CARDS = ")
        .append(new JSONArrayWriter(walletInternalJson.getArray(WalletCore.MATCHING_CARDS))
                .serializeToString(JSONOutputFormats.PRETTY_JS_NATIVE))
        .append(
            ";\n" +
            "let cardIndex = 0;\n" +
            "let cardImage = null;\n" +
                    
            "function selectCard() {\n" +
            "  let selectedCard = CARDS[cardIndex];\n" +
            "  cardImage.src='card?p1='+" +
                 "encodeURIComponent(selectedCard." + WalletCore.ACCOUNT_ID + ")+'&p2=' +" +
                 "encodeURIComponent(selectedCard." + WalletCore.CARD_HOLDER + ");\n" +
            "}\n" +
                 
            "let swipeStartPosition = null;\n" +
            
            "function unify(e) { return e.changedTouches ? e.changedTouches[0] : e };\n" +
            
            "function beginSwipe(e) { e.preventDefault(); swipeStartPosition = unify(e).clientX };\n" +
            
            "function endSwipe(e) {\n" +
            "  if (swipeStartPosition || swipeStartPosition === 0) {\n" +
            "    let dx = unify(e).clientX - swipeStartPosition;\n" +
            "    swipeStartPosition = null\n" +
            "    if (Math.abs(dx) > 30) {\n" +
            "      if (dx > 0 && cardIndex < CARDS.length - 1) {\n" +
            "        cardIndex++;\n" +
            "      } else if (dx < 0 && cardIndex > 0) {\n" +
            "        cardIndex--;\n" +
            "      } else {\n" +
            "        return;\n" +
            "      }\n" +
            "      selectCard();\n" +
            "    } else {\n" +
            //"      toast("Swipe to the left or right to change account/card", cardImage);\n" +
            "    }\n" +
            "  }\n" +
            "}\n" +
        
            "window.addEventListener('load', function(event) {\n" +
            "  cardImage = document.getElementById('card');\n" +
            "  cardImage.addEventListener('mousedown', beginSwipe, false);\n" +
            "  cardImage.addEventListener('touchstart', beginSwipe, false);\n" +

            "  cardImage.addEventListener('touchmove', e => { e.preventDefault() }, false);\n" +
            
            "  cardImage.addEventListener('mouseup', endSwipe, false);\n" +
            "  cardImage.addEventListener('touchend', endSwipe, false);\n" +
            
            "  selectCard();\n" +
            "  document.getElementById('" + ACTIVATE_ID + "').style.display = 'block';\n" +
            "});\n" +
            
            "function doContinue() {\n" +
            "  document.getElementById('" + ACTIVATE_ID + "').style.display = 'none';\n" +
            "  document.getElementById('" + WAITING_ID + "').style.display = 'block';\n" +
            "  document.getElementById('" + WalletCore.WALLET_INTERNAL + 
              "').value = JSON.stringify({" + WalletCore.PAYMENT_REQUEST + ": ")
        .append(paymentRequest.serializeToString(JSONOutputFormats.PRETTY_JS_NATIVE))
        .append(", " + WalletCore.SELECTED_CARD + ": CARDS[cardIndex]});\n" +
            "  setTimeout(function() {\n" +
            "    document.forms.shoot.submit();\n" +
            "  }, 500);\n" +
            "}\n").toString();

        HTML.standardPage(response, Actors.FWP, js, html); 
    }
}
