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

import java.util.ArrayList;

import java.util.logging.Logger;

import javax.servlet.ServletException;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.webpki.json.JSONArrayReader;
import org.webpki.json.JSONArrayWriter;
import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONObjectWriter;
import org.webpki.json.JSONOutputFormats;
import org.webpki.json.JSONParser;

/**
 * This is the request by the Merchant.
 *
 */
public class PaymentRequestServlet extends HttpServlet {
    
    static Logger logger = Logger.getLogger(PaymentRequestServlet.class.getName());

    private static final long serialVersionUID = 1L;
    
    // DIV elements to turn on and turn off.
    private static final String WAITING_ID     = "wait";
    private static final String ACTIVATE_ID    = "activate";

    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {
        request.setCharacterEncoding("utf-8");
        String walletRequest = request.getParameter(WalletCore.WALLET_REQUEST);
        if (walletRequest == null) {
            WalletCore.failed("Missing wallet request");
        }
        JSONObjectReader walletRequestJson = JSONParser.parse(walletRequest);
        try {
            // Get the enrolled user.
            String userId = WalletCore.getWalletCookie(request);
            if (userId == null) {
                response.sendRedirect("walletadmin");
                return;
            }
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
                String paymentNetwordId = network.getString("id");
                for (DataBaseOperations.VirtualCard virtualCard : virtualCards) {
                    if (paymentNetwordId.equals(virtualCard.paymentNetworkId)) {
                        if (matching == null) {
                            matching = new JSONArrayWriter();
                        }
                        matching.setObject(new JSONObjectWriter()
                            .setBinary(WalletCore.CREDENTIAL_ID, virtualCard.credentialId)
                            .setBinary(WalletCore.PUBLIC_KEY, virtualCard.publicKey)
                            .setString(WalletCore.ACCOUNT_ID, virtualCard.accountId)
                            .setString(WalletCore.CARD_HOLDER, virtualCard.cardHolder)
                            .setString(WalletCore.PAYMENT_NETWORK_ID, paymentNetwordId)
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
            
            StringBuilder html = new StringBuilder(
                "<form name='shoot' method='POST' action='ui'>" +
                "<input type='hidden' name='" + WalletCore.WALLET_INTERNAL + "' value='")
            .append(HTML.encode(walletInternal.serializeToString(JSONOutputFormats.NORMALIZED),
                                false))
            .append(
                "'/></form>" +
                "<div class='header'>Payment Request</div>" +
    
                "<div style='display:flex;justify-content:center;margin-top:15pt'>" +
                  "<div class='comment'>")
            .append(ADServlet.sectionReference("seq-1"))
            .append(
                  ": This is what the <span class='actor'>Merchant</span>'s " +
                  "call to the W3C PaymentRequest API " +
                  "boils down to, here expressed as JSON. The &quot;" + WalletCore.NETWORKS +
                  "&quot; array holds a list of FWP compatible payment networks that the " +
                  "<span class='actor'>Merchant</span> accepts." +
                 "</div>" +
                "</div>" +
                
                "<div style='display:flex;justify-content:center'>" +
                  "<img id='" + WAITING_ID + "' src='images/waiting.gif' " +
                      "style='padding-top:2em;display:none' alt='waiting'/>" +
                "</div>" +

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

                WalletCore.GO_HOME_JAVASCRIPT +
                
                "function doContinue() {\n" +
                "  document.getElementById('" + ACTIVATE_ID + "').style.display = 'none';\n" +
                "  document.getElementById('" + WAITING_ID + "').style.display = 'block';\n" +
                "  setTimeout(function() {\n" +
                "    document.forms.shoot.submit();\n" +
                "  }, 500);\n" +
                "}\n").toString();

            HTML.standardPage(response, Actors.FWP, js.toString(), html); 
        } catch (Exception e) {
            HTML.errorPage(response, e);
        }
    }
}
