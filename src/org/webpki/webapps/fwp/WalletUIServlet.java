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
 * This is the wallet UI when paying.
 *
 */
public class WalletUIServlet extends HttpServlet {
    
    static Logger logger = Logger.getLogger(WalletUIServlet.class.getName());

    private static final long serialVersionUID = 1L;
    
    private static final String NOTIFIER = "notifier";
    
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

            "<svg id='vertbar' style='position:absolute;visibility:hidden;z-index:5' " +
            "width='3' height='30' xmlns='http://www.w3.org/2000/svg'>" +
            "<rect x='0' y='0' width='3' height='30' rx='2' fill='grey'/>" +
            "</svg>" +
            
            "<div class='header'>Wallet UI</div>" +
            
            "<div id='" + NOTIFIER + "' class='toasting'>Swipe to the left or right...</div>" +
            
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
            "<div style='display:flex;align-items:center;flex-direction:column;" +
            "border-width:1px 2px 2px 1px;border-style:solid;border-color:black'>" +
            "<div style='width:100%;background-color:black'><div style='padding:0.3em 0.8em;color:white'>")
        .append(request.getServerName())
        .append(
            "</div></div>" +
            "<img id='card' src='' class='card' style='cursor:grab' title='Swipe a card!'/>" +
            "<table style='margin-top:1em'>" +
            "<tr><th style='text-align:right'>Payee</th><td>&nbsp;")
        .append(paymentRequest.getString(FWPPaymentRequest.JSON_PR_PAYEE_NAME))
        .append(
            "</td></tr>" +
            "<tr><th style='text-align:right'>Total</th><td>&nbsp;&#x20ac; ")
        .append(paymentRequest.getString(FWPPaymentRequest.JSON_PR_AMOUNT))
        .append(
            "</td></tr>" +
            "</table>" +
 
           "<img id='" + WAITING_ID + "' src='images/waiting.gif' " +
                  "style='padding-top:1.5em;display:none' alt='waiting'/>" +

            "<div style='display:none;margin-bottom:1.2em' id='" + ACTIVATE_ID + 
            "' class='stdbtn' onclick=\"doContinue()\">" +
                "Authorize..." +
            "</div>" +

            "</div>" +
            
            "<div style='margin-top:1em'>Yes, this is a <i>prototype</i> UI...</div>" +
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
            "        let box = cardImage.getBoundingClientRect();\n" +
            "        let e = document.getElementById('vertbar');\n" +
            "        e.style.top = (box.top + window.scrollY + (cardImage.offsetHeight - 30) / 2) + 'px';\n" +
            "        if (dx < 0) {\n" +
            "          e.style.left = (box.left + 7) + 'px';\n" +
            "        } else {\n" +
            "          e.style.left = (box.right - 10) + 'px';\n" +
            "        }\n" +
            "        e.style.visibility='visible';\n" +
            "        setTimeout(function() {\n" +
            "          e.style.visibility='hidden';\n" +
            "        }, 500);\n" +
            "        return;\n" +
            "      }\n" +
            "      selectCard();\n" +
            "    } else {\n" +
            "  let notifier = document.getElementById('" + NOTIFIER + "');\n" +
            "  notifier.style.top = (cardImage.getBoundingClientRect().top + window.scrollY + " +
                "notifier.offsetHeight) + 'px';\n" +
            "  notifier.style.left = ((window.innerWidth - notifier.offsetWidth) / 2) + 'px';\n" +
            "  notifier.style.visibility = 'visible';\n" +
            "  setTimeout(function() {\n" +
            "    notifier.style.visibility = 'hidden';\n" +
            "  }, 500);\n" +
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

        HTML.standardPage(response, Actors.WALLET, js, html); 
    }
}
