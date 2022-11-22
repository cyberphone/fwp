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

import org.webpki.cbor.CBORObject;

import org.webpki.crypto.HashAlgorithms;

import org.webpki.fwp.FWPAssertionBuilder;
import org.webpki.fwp.FWPCrypto;
import org.webpki.fwp.FWPPaymentRequest;

import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONParser;

/**
 * This FWP step creates Authorization Data (AD).
 *
 */
public class ADServlet extends HttpServlet {
    
    static Logger logger = Logger.getLogger(ADServlet.class.getName());

    private static final long serialVersionUID = 1L;
    
    // DIV elements to turn on and turn off.
    private static final String WAITING_ID     = "wait";
    private static final String FAILED_ID      = "fail";
    private static final String ACTIVATE_ID    = "activate";


    static String sectionReference(String section) {
        return "<a href='" + "https://fido-web-pay.github.io/specification#" + section +
                  "' target='_blank'>" + section + "</a>";
    }
    
    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {
        request.setCharacterEncoding("utf-8");
        String walletInternal = request.getParameter(WalletCore.WALLET_INTERNAL);
        if (walletInternal == null) {
            WalletCore.failed("Missing wallet data");
        }
        JSONObjectReader walletInternalJson = JSONParser.parse(walletInternal);
        try {
            // Get the enrolled user.
            String userId = WalletCore.getWalletCookie(request);
            if (userId == null) {
                response.sendRedirect("walletadmin");
                return;
            }
            
            SystemDetection system = new SystemDetection(request.getHeader("user-agent"));

            // Build Authorization Data (AD)
            JSONObjectReader selectedCard =
                    walletInternalJson.getObject(WalletCore.SELECTED_CARD);
            JSONObjectReader paymentRequest =
                    walletInternalJson.getObject(WalletCore.PAYMENT_REQUEST);
            byte[] unsignedAssertion = new FWPAssertionBuilder()
                .setPaymentRequest(new FWPPaymentRequest(paymentRequest))
                .setPaymentInstrumentData(selectedCard.getString(WalletCore.ACCOUNT_ID),
                                          selectedCard.getString(WalletCore.SERIAL_NUMBER),
                                          selectedCard.getString(WalletCore.PAYMENT_NETWORK_ID))
                .setPayeeHost(request.getServerName())
                .setPlatformData(system.operatingSystemName,
                                 system.operatingSystemVersion,
                                 system.browserName,
                                 system.browserVersion)
                .create(new FWPCrypto.FWPPreSigner(selectedCard.getBinary(WalletCore.PUBLIC_KEY)));
             
            StringBuilder html = new StringBuilder(
                "<form name='shoot' method='POST' action='sad'>" +
                "<input type='hidden' id='" + WalletCore.FWP_SAD + 
                    "' name='" + WalletCore.FWP_SAD + "'/>" +
                "<input type='hidden' name='" + WalletCore.WALLET_INTERNAL + "' value='")
            .append(HTML.encode(walletInternal, false))
            .append(
                "'/>" +
                "</form>" +

                "<div class='header'>Authorization Data (AD)</div>" +

                "<div style='display:flex;justify-content:center;margin-top:15pt'>" +
                  "<div class='comment'>")
            .append(sectionReference("seq-4.2"))
            .append(
                  ": The payment data to authorize. " +
                  "AD represents the sole data input to the FIDO signature process." +
                  "<div style='margin-top:0.4em'>That is, <i>there is no FIDO authentication " +
                  "server involved</i> since FWP builds on the same " +
                  "&quot;Card&nbsp;Present&quot; <i>authorization</i> concept as " +
                  "<a href='https://www.emvco.com/about/deployment-statistics/' " +
                  "target='_blank'>EMV&reg;</a> and " + 
                  "<a href='https://www.apple.com/apple-pay/' target='_blank'>Apple Pay&reg;</a>.</div>" +
                  "<div style='margin-top:0.4em'>The data is shown in " +
                  "<a href='https://fido-web-pay.github.io/specification/#cbor' " +
                  "target='_blank'>CBOR</a> diagnostic notation.</div>" +
                 "</div>" +
                "</div>" +
                
                "<div style='display:flex;justify-content:center'>" +
                  "<img id='" + WAITING_ID + "' src='images/waiting.gif' " +
                      "style='padding-top:2em;display:none' alt='waiting'/>" +
                "</div>" +

                "<div id='" + FAILED_ID + "' class='errorText'></div>" +

                "<div style='display:flex;justify-content:center'>" +
                  "<div id='" + ACTIVATE_ID + "' class='stdbtn' onclick=\"doPay()\">" +
                    "Authorize (Sign) using FIDO..." +
                  "</div>" +
                "</div>" +

                "<div class='staticbox'>")
            .append(HTML.encode(CBORObject.decode(unsignedAssertion).toString(), true))
            .append(
                "</div>");

            String js = new StringBuilder(

                WalletCore.GO_HOME_JAVASCRIPT +
                
                "const serviceUrl = 'fidopay';\n" +

                WalletCore.FWP_JAVASCRIPT +

                "async function doPay() {\n" +
                "  try {\n" +
                "    document.getElementById('" + ACTIVATE_ID + "').style.display = 'none';\n" +
                "    document.getElementById('" + WAITING_ID + "').style.display = 'block';\n" +

                "    const options = {\n" +
                "      challenge: b64urlToU8arr('" +
                            ApplicationService.base64UrlEncode(
                                    HashAlgorithms.SHA256.digest(unsignedAssertion)) +
                       "'),\n" +

                "      allowCredentials: [{type: 'public-key', " +
                           "id: b64urlToU8arr('" + 
                                              selectedCard.getString(WalletCore.CREDENTIAL_ID) +
                                              "')}],\n" +

                "      userVerification: '" + WalletCore.USER_VERIFICATION + "',\n" +

                "      timeout: 120000\n" +
                "    };\n" +
                
//                "    console.log(options);\n" +
                "    const result = await navigator.credentials.get({ publicKey: options });\n" +
//                "    console.log(result);\n" +
                "    const returnJson = await exchangeJSON({" + 

                         FWPCrypto.AUTHENTICATOR_DATA + 
                         ":arrBufToB64url(result.response.authenticatorData)," +

                         FWPCrypto.SIGNATURE + 
                         ":arrBufToB64url(result.response.signature)," +

                         FWPCrypto.CLIENT_DATA_JSON + 
                         ":arrBufToB64url(result.response.clientDataJSON)," +

                         WalletCore.FWP_AD + 
                         ": '" + 
                         ApplicationService.base64UrlEncode(unsignedAssertion) +
                         "'}, null);\n" +

                "    document.getElementById('" + WalletCore.FWP_SAD + 
                    "').value = returnJson." + WalletCore.FWP_SAD + ";\n" +
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
            HTML.standardPage(response, Actors.FWP, js, html);
        } catch (Exception e) {
            HTML.errorPage(response, e);
        }
    }
}
