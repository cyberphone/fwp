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

import java.util.Base64;

import java.util.logging.Logger;

import javax.servlet.ServletException;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.webpki.cbor.CBORObject;

import org.webpki.fwp.FWPAssertionBuilder;
import org.webpki.fwp.FWPCrypto;
import org.webpki.fwp.FWPElements;
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
        String walletInternal = request.getParameter(FWPWalletCore.WALLET_INTERNAL);
        if (walletInternal == null) {
            FWPWalletCore.failed("Missing wallet data");
        }
        logger.info(walletInternal);
        JSONObjectReader walletInternalJson = JSONParser.parse(walletInternal);
        try {
            // Get the enrolled user.
            String userId = FWPWalletCore.getWalletCookie(request);
            if (userId == null) {
                response.sendRedirect("walletadmin");
                return;
            }

            // Build Authorization Data (AD)
            JSONObjectReader selectedCard =
                    walletInternalJson.getObject(FWPWalletCore.SELECTED_CARD);
            JSONObjectReader paymentRequest =
                    walletInternalJson.getObject(FWPWalletCore.PAYMENT_REQUEST);
             byte[] fwpAssertion = new FWPAssertionBuilder()
                    .setPaymentRequest(new FWPPaymentRequest(paymentRequest))
                    .setAccountData(selectedCard.getString(FWPWalletCore.ACCOUNT_ID),
                                    selectedCard.getString(FWPWalletCore.SERIAL_NUMBER),
                                    selectedCard.getString(FWPWalletCore.PAYMENT_METHOD))
                    .setUserAuthorizationMethod(FWPElements.UserAuthorizationMethods.FINGERPRINT)
                    .setPayeeHost(request.getServerName())
                    .setPlatformData("Android", "10.0", "Chrome", "103")
                    .create(new FWPCrypto.FWPPreSigner(
                            selectedCard.getBinary(FWPWalletCore.PUBLIC_KEY)));
             
            StringBuilder html = new StringBuilder(
                "<form name='shoot' method='POST' action='sad'>" +
                "<input type='hidden' id='" + FWPWalletCore.FWP_SAD + 
                    "' name='" + FWPWalletCore.FWP_SAD + "'/>" +
                "<input type='hidden' name='" + FWPWalletCore.WALLET_INTERNAL + "' value='")
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
                  "This data is (after SHA256-digesting), used as the FIDO &quot;challenge&quot;. " +
                  "That is, <i>there is no FIDO authentication server</i> because FWP builds on a " +
                  "&quot;Card&nbsp;Present&quot; <i>authorization</i> concept like " +
                  "<a href='https://www.emvco.com/about/deployment-statistics/' " +
                  "target='_blank'>EMV&reg;</a> and " + 
                  "<a href='https://www.apple.com/apple-pay/' target='_blank'>Apple Pay&reg;</a>." +
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
            .append(HTML.encode(CBORObject.decode(fwpAssertion).toString(), true)
                    .replace("9:&nbsp;", 
                             "<span style='color:grey;word-break:normal'>// The platform data is " +
                               "currently not authentic</span><br>&nbsp;&nbsp;9:&nbsp;"))
            .append(
                "</div>");

            String js = new StringBuilder(

                FWPWalletCore.GO_HOME_JAVASCRIPT +
                
                "const serviceUrl = 'fidopay';\n" +

                FWPWalletCore.FWP_JAVASCRIPT +

                "async function doPay() {\n" +
                "  try {\n" +
                "    document.getElementById('" + ACTIVATE_ID + "').style.display = 'none';\n" +
                "    document.getElementById('" + WAITING_ID + "').style.display = 'block';\n" +
                "    const initPhase = await exchangeJSON({" + FWPWalletCore.FWP_AD + 
                  ": '" + 
                  Base64.getUrlEncoder().withoutPadding().encodeToString(fwpAssertion) +
                  "'},'" + FWPWalletCore.INIT_PHASE + "');\n" +

                "    const options = {\n" +
                "      challenge: b64urlToU8arr(initPhase." + FWPCrypto.CHALLENGE + "),\n" +

                "      allowCredentials: [{type: 'public-key', " +
                           "id: b64urlToU8arr('" + 
                                              selectedCard.getString(FWPWalletCore.CREDENTIAL_ID) 
                                              + "')}],\n" +

                "      userVerification: 'preferred',\n" +

                "      timeout: 120000\n" +
                "    };\n" +
                
//                "    console.log(options);\n" +
                "    const result = await navigator.credentials.get({ publicKey: options });\n" +
//                "    console.log(result);\n" +
                "    const finalizePhase = await exchangeJSON({" + 

                             FWPCrypto.AUTHENTICATOR_DATA_JSON + 
                             ":arrBufToB64url(result.response.authenticatorData)," +

                             FWPCrypto.SIGNATURE_JSON + 
                             ":arrBufToB64url(result.response.signature)," +

                             FWPCrypto.CLIENT_DATA_JSON_JSON + 
                             ":arrBufToB64url(result.response.clientDataJSON)},'" +

                             FWPWalletCore.FINALIZE_PHASE + "');\n" +

                "    document.getElementById('" + FWPWalletCore.FWP_SAD + 
                    "').value = finalizePhase." + FWPWalletCore.FWP_SAD + ";\n" +
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
