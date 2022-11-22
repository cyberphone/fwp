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
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.logging.Logger;

import javax.servlet.ServletException;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.webpki.fwp.FWPPaymentRequest;

import org.webpki.json.JSONArrayReader;
import org.webpki.json.JSONArrayWriter;
import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONObjectWriter;
import org.webpki.json.JSONOutputFormats;
import org.webpki.json.JSONParser;

/**
 * This is a checkout application.
 *
 */
public class BuyServlet extends HttpServlet {
    
    static Logger logger = Logger.getLogger(BuyServlet.class.getName());

    private static final long serialVersionUID = 1L;
    
    private static final String NOTIFIER = "notifier";
    
    private static final String OPTIONAL_ERROR = "opterr";
    
    // DIV elements to turn on and turn off.
    private static final String WAITING_ID     = "wait";
    private static final String ACTIVATE_ID    = "activate";
    
    private static String lastDate;
    private static int lastCount;
    static synchronized String getRequestId() {
        String newDate = new SimpleDateFormat("yyyyMMdd.").format(new Date());
        if (!newDate.equals(lastDate)) {
            lastDate = newDate;
            lastCount = 0;
        }
        return lastDate + String.format("%04d", ++lastCount);
    }

    public void doGet(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {
        FWPPaymentRequest samplePaymentRequest = 
                new FWPPaymentRequest("Space Shop", getRequestId(), "435.00", "EUR");
        StringBuilder html = new StringBuilder(
            "<form name='shoot' method='POST' action='buy'>" +
        
            "<input type='hidden' id='" + WalletCore.WALLET_REQUEST + 
                "' name='" + WalletCore.WALLET_REQUEST + "'/>" +

            "<div class='header'>Checkout Time!</div>" +

            "<div style='display:flex;justify-content:center;margin-top:15pt'>" +
              "<div class='comment'>" +
                  "Since this proof-of-concept and test application is only about " +
                  "payments, the shopping session is assumed to already have been " +
                  "carried out.  Here you just pay &#x20ac;&#x2009;435 using " +
                  "demo credentials issued by a non-existing bank &#x1f60e;" +
                  "<table style='margin-top:0.5em;border-spacing:0'>" +
                  "<tr><td><input type='checkbox' onchange='setMode(this.checked)'></td>" +
                  "<td>Step-by-step technical demo</td></tr></table>" +
              "</div>" +
            "</div>" +

            "<div class='header' style='margin:1em 0'>Select Payment Method</div>" +
            
            "<div id='" + NOTIFIER + "' class='toasting'>This demo only supports FWP...</div>" +
            
            "<div style='display:flex;align-items:center;flex-direction:column'>" +
              "<img src='images/fwpminiplus-pay.svg' class='payimage' " +
                 "onclick='doPay()' alt='image'/>" +
              "<img src='images/paypal-pay.svg' class='payimage' " +
                  "onclick='unsupported(this)' style='margin:1.2em 0' alt='image'/>" +
              "<img src='images/legacy-visamc-pay.svg' class='payimage' " + 
                 "onclick='unsupported(this)' alt='image'/>" +
            "</div>" +
             
            "<div style='display:flex;justify-content:center;margin-top:15pt'>" +
              "<div style='max-width:40em'>" +
                "<a href='https://fido-web-pay.github.io' target='_blank'>FIDO Web Pay</a> " +
                "follows the FIDO paradigm by being <i>provider neutral</i>, " +
                "making the user experience <i>identical</i> when performing a " +
                "SEPA instant payment or using an international card network like VISA." +
              "</div>" +
            "</div>" +
            
            "</form>");

        String js = new StringBuilder(
            "const paymentRequest = ")
        .append(samplePaymentRequest.serializeAsJSON(JSONOutputFormats.PRETTY_JS_NATIVE))
        .append(
            ";\n" +
        
            "const networks = [\n" +
            "  {id: 'https://banknet2.org'},\n" +
            "  {id: 'https://othernet.com'},\n" +
            "  {id: 'https://supercard.com'}\n" +
            "]\n" +
         
            "function unsupported(target) {\n" +
            "  let notifier = document.getElementById('" + NOTIFIER + "');\n" +
            "  notifier.style.top = (target.getBoundingClientRect().top + window.scrollY - " +
                "notifier.offsetHeight) + 'px';\n" +
            "  notifier.style.left = ((window.innerWidth - notifier.offsetWidth) / 2) + 'px';\n" +
            "  notifier.style.visibility = 'visible';\n" +
            "  setTimeout(function() {\n" +
            "    notifier.style.visibility = 'hidden';\n" +
            "  }, 500);\n" +
            "}\n\n" +

            "function doPay() {\n" +
            "  document.getElementById('" + WalletCore.WALLET_REQUEST + 
                "').value = JSON.stringify({" + 
                WalletCore.PAYMENT_REQUEST + ": paymentRequest, " +
                WalletCore.NETWORKS + ": networks});\n" +
            "  document.forms.shoot.submit();\n" +
            "}\n" +
            
            "function setMode(stepByStep) {\n" +
            "  document.forms.shoot.action = stepByStep ? 'pr' : 'buy';\n" +
            "}\n").toString();
        HTML.standardPage(response, Actors.MERCHANT, js, html);
    }
    
    void resultPage(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {
        String error = request.getParameter(OPTIONAL_ERROR);
        StringBuilder html = new StringBuilder(
            error.isEmpty() ? 
            "<div style='display:flex;justify-content:center;margin-top:4em'>" +
              "<img src='images/spaceshop-logo.svg' alt='logo' " +
                "onclick=\"document.location.href='buy'\" " +
                "style='max-width:90%;cursor:pointer' " +
                "title='click to test again'>" +
            "</div>" +
            
            "<div style='display:flex;justify-content:center;margin-top:2em'>" +
              "<div class='comment'>" +
              "Thank you for your order and welcome back!" +
              "</div>" +
            "</div>"
              :
            "<div class='header' style='margin-top:1em'>Error</div>" +
              
            "<div style='display:flex;justify-content:center;margin-top:15pt'>" +
            "<div style='font-weight:bold;color:red'>")
       .append(HTML.encode(error, false))
       .append(
            "</div>" +
            "</div>");

        HTML.standardPage(response, Actors.MERCHANT, WalletCore.GO_HOME_JAVASCRIPT, html); 
    }
    
    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {
        request.setCharacterEncoding("utf-8");

        // Get the enrolled user.
        String userId = WalletCore.getWalletCookie(request);
        if (userId == null) {
            response.sendRedirect("walletadmin");
            return;
        }
        try {
            String walletRequest = request.getParameter(WalletCore.WALLET_REQUEST);
            if (walletRequest == null) {
                // User statistics...
                try (Connection connection = ApplicationService.jdbcDataSource.getConnection();) {
                    DataBaseOperations.updateUserStatistics(userId, false, connection);
                }           
                resultPage(request, response);
                return;
            }
            JSONObjectReader walletRequestJson = JSONParser.parse(walletRequest);

            // What the Merchant wants...
            JSONObjectReader paymentRequest =
                    walletRequestJson.getObject(WalletCore.PAYMENT_REQUEST);
            
            // Lookup virtual cards in the wallet database
            ArrayList<DataBaseOperations.VirtualCard> virtualCards;
            try (Connection connection = ApplicationService.jdbcDataSource.getConnection();) {
                virtualCards = DataBaseOperations.getVirtualCards(userId, connection);
            }
            if (virtualCards.isEmpty()) {
                response.sendRedirect("walletadmin");
                return;
            }

            // Match against Merchant list
            JSONArrayWriter matching = null;
            JSONArrayReader networks = walletRequestJson.getArray(WalletCore.NETWORKS);
            while (networks.hasMore()) {
                JSONObjectReader network = networks.getObject();
                String paymentNetworkId = network.getString("id");
                for (DataBaseOperations.VirtualCard virtualCard : virtualCards) {
                    if (paymentNetworkId.equals(virtualCard.paymentNetworkId)) {
                        if (matching == null) {
                            matching = new JSONArrayWriter();
                        }
                        matching.setObject(new JSONObjectWriter()
                                .setBinary(WalletCore.CREDENTIAL_ID, virtualCard.credentialId)
                                .setBinary(WalletCore.PUBLIC_KEY, virtualCard.publicKey)
                                .setString(WalletCore.ACCOUNT_ID, virtualCard.accountId)
                                .setString(WalletCore.CARD_HOLDER, virtualCard.cardHolder)
                                .setString(WalletCore.PAYMENT_NETWORK_ID, paymentNetworkId)
                                .setString(WalletCore.SERIAL_NUMBER, virtualCard.serialNumber)
                                // Hard-coded at the moment
                                .setString(WalletCore.ISSUER_ID, ApplicationService.issuerId));
                    }
                }
            }
            if (matching == null) {
                throw new IOException("No matching card");
            }
            
            JSONObjectWriter walletInternal = new JSONObjectWriter()
                    .setObject(WalletCore.PAYMENT_REQUEST, paymentRequest)
                    .setArray(WalletCore.MATCHING_CARDS, matching);
            
            JSONObjectReader walletInternalJson = new JSONObjectReader(walletInternal);
            
            StringBuilder html = new StringBuilder(
                    "<form name='shoot' method='POST' action='buy'>" +
                    "<input type='hidden' id='" + OPTIONAL_ERROR + "' name='" +
                                                  OPTIONAL_ERROR + "'/>" +
                    "</form>" +

                    "<svg id='vertbar' style='position:absolute;visibility:hidden;z-index:5' " +
                    "width='3' height='30' xmlns='http://www.w3.org/2000/svg'>" +
                    "<rect x='0' y='0' width='3' height='30' rx='2' fill='grey'/>" +
                    "</svg>" +
                    
                    "<div class='header'>Wallet UI</div>" +
                    
                    "<div id='" + NOTIFIER + "' class='toasting'>Swipe to the left or right...</div>" +
                    
                    "<div style='display:flex;justify-content:center;margin-top:15pt'>" +
                      "<div class='comment'>" +
                      "Select a payment card and authorize the payment request. " +
                      "Only the cards in the " +
                      "<span class='actor'>Wallet</span> matching the " +
                      "list of supported payment networks supplied by the " +
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
                    "' class='stdbtn' onclick=\"doAuthorize()\">" +
                        "Authorize..." +
                    "</div>" +

                    "</div>" +
                    
                    "<div style='margin-top:1em'>Yes, this is a <i>prototype</i> UI...</div>" +
                    "</div>");
                

                String js = new StringBuilder(

                    WalletCore.GO_HOME_JAVASCRIPT +

                    // Not used but must be defined
                    "const serviceUrl = null;\n" +

                    WalletCore.FWP_JAVASCRIPT +

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
                    
                    "async function doAuthorize() {\n" +
                    "  try {\n" +
                    "    document.getElementById('" + ACTIVATE_ID + "').style.display = 'none';\n" +
                    "    document.getElementById('" + WAITING_ID + "').style.display = 'block';\n" +
                    
                    "    const options = {\n" +
                    // Any 32 bytes will do since we don't run the whole thing...
                    "      challenge: b64urlToU8arr('mCbcvUzm44j3Lt2b5BPyQloQ91tf2D2V-gzeUxWaUdg'),\n" +

                    "      allowCredentials: [{type: 'public-key', " +
                               "id: b64urlToU8arr(CARDS[cardIndex]. " + WalletCore.CREDENTIAL_ID +
                           ")}],\n" +

                    "      userVerification: '" + WalletCore.USER_VERIFICATION + "',\n" +

                    "      timeout: 120000\n" +
                    "    };\n" +

                    "    const result = await navigator.credentials.get({ publicKey: options });\n" +
                    "    console.log(result);\n" +
                    
                    // Errors are effectively aborting so a single try-catch does the trick.
                    "  } catch (error) {\n" +
                    "    document.getElementById('" + OPTIONAL_ERROR + "').value = error;\n" +
                    "    console.log('fail:' + error);\n" +
                    "  }\n" +

                    "  document.forms.shoot.submit();\n" +

                    "}\n").toString();

            // Refresh the persistent cookie. 
            FIDOEnrollServlet.setWalletCookie(response, userId);

            HTML.standardPage(response, Actors.WALLET, js, html); 

        } catch (Exception e) {
            HTML.errorPage(response, e);
        }
    }
}
