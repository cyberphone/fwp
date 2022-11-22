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

import java.net.URLEncoder;

import java.sql.Connection;

import java.util.ArrayList;

import java.util.logging.Logger;

import javax.servlet.ServletException;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.webpki.fwp.FWPCrypto;

public class EnrollServlet extends HttpServlet {
    
    static Logger logger = Logger.getLogger(EnrollServlet.class.getName());

    private static final long serialVersionUID = 1L;

    // HTML form arguments.
    private static final String DEFAULT_CARD_HOLDER_NAME  = "Anonymous Tester &#x1f638;";
    private static final String CARD_HOLDER_NAME          = "chn";
    
    // DIV elements to turn on and turn off.
    private static final String WAITING_ID        = "wait";
    private static final String USER_IFC_ID       = "uifc";
    private static final String FAILED_ID         = "fail";
    
    public void doGet(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {
        try {
            boolean alreadyEnrolled = WalletCore.hasPaymentCards(request);
            StringBuilder html = new StringBuilder(alreadyEnrolled ?
                "<div class='header'>Enroll Payment Cards</div>" +
    
                "<div class='important'>" +
                  "You already have enrolled payment cards" +
                "</div>" +
    
                "<div style='display:flex;justify-content:center'>" +
                  "<table>" +
                    WalletAdminServlet.WALLET_ADMIN_BUTTON +
                  "</table>" +
                "</div>"
                                     :
                "<form name='shoot' method='POST' action='enroll'>" +
    
                "<div class='header'>Enroll Payment Cards</div>" +
    
                "<div style='display:flex;justify-content:center;margin-top:15pt'>" +
                  "<div class='comment'>" +
                      "In a real-world setting, you would enroll payment cards at an " +
                       "<span class='actor'>Issuer</span> site " +
                      "(after being authenticated using an <i>issuer-specific method</i>)." +
                  "</div>" +
                "</div>" +
    
                "<div style='display:flex;justify-content:center'>" +
                  "<img id='" + WAITING_ID + "' src='images/waiting.gif' " +
                      "style='padding-top:5em;display:none' alt='waiting'/>" +
                "</div>" +
                
                "<div id='" + FAILED_ID + "' class='errorText'></div>" +
    
                "<div id='" + USER_IFC_ID + "'>" +
                  "<div style='display:flex;justify-content:center;margin-top:15pt'><table>" +
                    "<tr><td>Card Holder:</td></tr>" +
                    "<tr><td><input type='text' id='" + CARD_HOLDER_NAME + "' " +
                        "maxlength='50' value='" + DEFAULT_CARD_HOLDER_NAME + 
                        "' style='background-color:#def7fc;padding:2pt 3pt' autofocus></td></tr>" +
                  "</table></div>" +
    
                  "<div style='display:flex;justify-content:center'>" +
                    "<div class='stdbtn' onclick=\"doEnroll()\">" +
                      "Start Enrollment!" +
                    "</div>" +
                  "</div>" +
                "</div>" +
                
                "</form>");
    
            String js = alreadyEnrolled ? null : new StringBuilder(
                "const serviceUrl = 'fidoenroll';\n" +

                WalletCore.FWP_JAVASCRIPT +

                "async function doEnroll() {\n" +
                "  try {\n" +
                "    document.getElementById('" + USER_IFC_ID + "').style.display = 'none';\n" +
                "    document.getElementById('" + WAITING_ID + "').style.display = 'block';\n" +
                "    const initPhase = await exchangeJSON({" +
                         WalletCore.CARD_HOLDER + ":" +
                         "document.getElementById('" + CARD_HOLDER_NAME + 
                         "').value},'" + WalletCore.INIT_PHASE + "');\n" +
     
                "    let publicKey = {\n" +
                "      challenge: b64urlToU8arr(initPhase." + FWPCrypto.CHALLENGE + "),\n" +
                "      rp: {\n" +
                "        name: 'FIDO Web Pay'\n" +
                "      },\n" +
                "      user: {\n" +
                "        id: new TextEncoder().encode(initPhase." + FWPCrypto.USER_ID + "),\n" +
                "        name: initPhase." + WalletCore.CARD_HOLDER + ",\n" +
                "        displayName: 'FWP User'\n" +
                "      },\n" +
                "      pubKeyCredParams: [{\n" +
                "        type: 'public-key',\n" +
                "        alg: " + FWPCrypto.FIDO_KEYALG_ED25519  + "\n" +
                "      },{\n" +
                "        type: 'public-key',\n" +
                "        alg: " + FWPCrypto.FIDO_KEYALG_ES256  + "\n" +
                "      },{\n" +
                "        type: 'public-key',\n" +
                "        alg: " + FWPCrypto.FIDO_KEYALG_RS256  + "\n" +
                "      }],\n" +
                "      timeout: 360000,\n" +
                "      excludeCredentials: [],\n" +
                "      authenticatorSelection: {\n" +
                "        residentKey: 'preferred',\n" +
                "        userVerification: '" + WalletCore.USER_VERIFICATION + "'\n" +
                "      },\n" +
// Attestation on Android is very slow so we drop this for the PoC :(
//                "      attestation: 'direct',\n" +
                "      attestation: 'none',\n" +
                "      extensions: {}\n" +
                "    };\n" +
                
//                "  console.log(publicKey);\n" +
                "    const result = await navigator.credentials.create({publicKey});\n" +
//                "    console.log(result);\n" +
                "    const finalizePhase = await exchangeJSON({" + 

                         // Core FIDO return data
                         FWPCrypto.ATTESTATION_OBJECT + 
                         ":arrBufToB64url(result.response." + FWPCrypto.ATTESTATION_OBJECT + ")," +

                         FWPCrypto.CLIENT_DATA_JSON + 
                         ":arrBufToB64url(result.response." + FWPCrypto.CLIENT_DATA_JSON + ")},'" +

                         WalletCore.FINALIZE_PHASE + "');\n" +

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
            HTML.standardPage(response, Actors.ISSUER, js, html);
        } catch (Exception e) {
            HTML.errorPage(response, e);
        }
    }
    
    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {
        try {
            // Get the enrolled user.
            String userId = WalletCore.getWalletCookie(request);
            
            ArrayList<DataBaseOperations.VirtualCard> virtualCards;
            try (Connection connection = ApplicationService.jdbcDataSource.getConnection();) {
                virtualCards = DataBaseOperations.getVirtualCards(userId, connection);
            }
            StringBuilder html = new StringBuilder(
                "<div class='header'>Enrollment Succeeded</div>" +
    
                "<div style='display:flex;justify-content:center;margin-top:15pt'>" +
                "<div class='comment'>" +
                "The following cards have been added to your FWP wallet." +
                "</div>" +
                "</div>" +
                "<div style='display:flex;align-items:center;flex-direction:column'>" +
             
                "<div style='display:flex;align-items:center;flex-direction:column'>");
            
            for (DataBaseOperations.VirtualCard virtualCard : virtualCards) {
                html.append("<img src='card?p1=")
                    .append(URLEncoder.encode(virtualCard.accountId, "utf-8"))
                    .append("&p2=")
                    .append(URLEncoder.encode(virtualCard.cardHolder, "utf-8"))
                    .append("' class='card' title='")
                    .append(virtualCard.accountId.startsWith("FR") ? "SEPA Card" : "Card Network")
                    .append("'/>");
            }
    
            html.append(
                "</div>" +
                "</div>" +
            
                "<div style='display:flex;justify-content:center'>" +
                  "<div class='stdbtn' onclick=\"document.location.href='buy'\">" +
                      "Buy Something..." +
                  "</div>" +
                "</div>");
            HTML.standardPage(response, Actors.WALLET, null, html);
        } catch (Exception e) {
            HTML.errorPage(response, e);
        }
    }
}
