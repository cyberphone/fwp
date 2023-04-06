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

import java.util.logging.Logger;

import javax.servlet.ServletException;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.webpki.cbor.CBORObject;
import org.webpki.cbor.CBORPublicKey;

import org.webpki.util.HexaDecimal;

import org.webpki.crypto.KeyAlgorithms;

import org.webpki.fwp.FWPCrypto;

/**
 * Enrolled credentials can also be used for FIDO/WebAuthn.
 *
 */
public class LoginServlet extends HttpServlet {
    
    static Logger logger = Logger.getLogger(LoginServlet.class.getName());

    private static final long serialVersionUID = 1L;
    
    // DIV elements to turn on and turn off.
    private static final String WAITING_ID     = "wait";
    private static final String FAILED_ID      = "fail";
    private static final String ACTIVATE_ID    = "activate";

    
    public void doGet(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {
        StringBuilder html = new StringBuilder(
            "<form name='shoot' method='POST' action='login'>" +

            "<div class='header'>Login Test</div>" +

            "<div style='display:flex;justify-content:center;margin-top:15pt'>" +
              "<div class='comment'>" +
                  "Although login is not a part of FIDO Web Pay, associated FIDO authenticators " +
                  "can <i>optionally</i> be used for authentication as well." +
                  "<div style='margin-top:0.4em'>Note that for <i>authentication</i> (unlike " +
                  "for payments), normal FIDO domain constraints apply.  That is, " +
                  "logins are restricted to the actual <span class='actor'>Issuer</span>.</div>" +
              "</div>" +
            "</div>" +
            
            "<div style='display:flex;justify-content:center'>" +
              "<img id='" + WAITING_ID + "' src='images/waiting.gif' " +
                  "style='padding-top:2em;display:none' alt='waiting'/>" +
            "</div>" +

            "<div id='" + FAILED_ID + "' class='errorText'></div>" +

            "<div style='display:flex;justify-content:center'>" +
              "<div id='" + ACTIVATE_ID + "' class='stdbtn' onclick=\"doLogin()\">" +
                "Login..." +
              "</div>" +
            "</div>" +
            "</form>");

        String js = new StringBuilder(
            "const serviceUrl = 'fidologin';\n" +

            WalletCore.FWP_JAVASCRIPT +

            "async function doLogin() {\n" +
            "  try {\n" +
            "    document.getElementById('" + ACTIVATE_ID + "').style.display = 'none';\n" +
            "    document.getElementById('" + WAITING_ID + "').style.display = 'block';\n" +
            "    const initPhase = await exchangeJSON({},'" + WalletCore.INIT_PHASE + "');\n" +

            "    const options = {\n" +
            "      challenge: b64urlToU8arr(initPhase." + FWPCrypto.CHALLENGE + "),\n" +

            "      allowCredentials: [{type: 'public-key', " +
                       "id: b64urlToU8arr(initPhase." + FWPCrypto.CREDENTIAL_ID + ")}],\n" +

            "      userVerification: '" + WalletCore.USER_VERIFICATION + "',\n" +

            "      timeout: 120000\n" +
            "    };\n" +
            
//            "    console.log(options);\n" +
            "    const result = await navigator.credentials.get({ publicKey: options });\n" +
//            "    console.log(result);\n" +
            "    const finalizePhase = await exchangeJSON({" + 

                         FWPCrypto.AUTHENTICATOR_DATA + 
                         ":arrBufToB64url(result.response.authenticatorData)," +

                         FWPCrypto.SIGNATURE + 
                         ":arrBufToB64url(result.response.signature)," +

                         FWPCrypto.CLIENT_DATA_JSON + 
                         ":arrBufToB64url(result.response.clientDataJSON)},'" +

                         WalletCore.FINALIZE_PHASE + "');\n" +

            "    document.forms.shoot.submit();\n" +

            // Errors are effectively aborting so a single try-catch does the trick.
            "  } catch (error) {\n" +
            "    if (error == '" + FIDOLoginServlet.MISSING_ENROLL + "') {\n" +
            "      document.location.href = 'walletadmin';\n" +
            "      return;\n" +
            "    }\n" +
            "    let message = 'Fail: ' + error;\n" +
            "    console.log(message);\n" +
            "    document.getElementById('" + WAITING_ID + "').style.display = 'none';\n" +
            "    let e = document.getElementById('" + FAILED_ID + "');\n" +
            "    e.textContent = message;\n" +
            "    e.style.display = 'block';\n" +
            "  }\n" +

            "}\n").toString();
        HTML.standardPage(response, Actors.ISSUER, js, html);
    }
    
    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {
        try {
            // Get the enrolled user.
            String userId = WalletCore.getWalletCookie(request);
            if (userId == null) {
                WalletCore.failed("User ID missing, have you enrolled?");
            }
            
            // Lookup in database
            DataBaseOperations.CoreClientData coreClientData;
            try (Connection connection = ApplicationService.jdbcDataSource.getConnection();) {
                // Get the anticipated public key
                coreClientData = DataBaseOperations.getCoreClientData(userId, connection);
            }
            
            HttpSession session = request.getSession(false);
            
            if (session == null) {
                WalletCore.failed("No session!");
            }
            
            CBORObject publicKey = CBORObject.decode(coreClientData.cosePublicKey);
            
            StringBuilder html = new StringBuilder(
                    "<div class='header'>Login Succeeded!</div>" +
            
                    "<div style='display:flex;justify-content:center;margin-top:15pt'>" +
                      "<div class='comment'>" +
                         "This is what the login returned from the " +
                         "<span class='actor'>Issuer</span> database " +
                         "and from the assertion." +
                      "</div>" +
                    "</div>" +

                    "<div style='display:flex;align-items:center;flex-direction:column;margin-top:15pt'>" +
                        "<div class='ctblh'>Card Holder</div>" +
                        "<div style='padding-bottom:1em'>")
                .append(HTML.encode(coreClientData.cardHolder, false))
                .append("</div>" +

                        "<div class='ctblh'>User ID</div>" +
                        "<div class='ctbl'>")
                .append(userId)
                .append("</div>" +
                
                        "<div class='ctblh'>Web Session ID</div>" +
                        "<div class='ctbl'>")
                .append(session.getId())
                .append("</div>" +
                
                        "<div class='ctblh'>FIDO Credential ID (B64U)</div>" +
                        "<div class='ctbl'>")
                .append(ApplicationService.base64UrlEncode(coreClientData.credentialId))
                .append("</div>" +

                        "<div class='ctblh'>RP ID</div>" +
                        "<div class='ctbl'>")
                .append(coreClientData.rpId)
                .append("</div>" +

                        "<div class='ctblh'>FIDO Authenticator Data (HEX)</div>" +
                        "<div class='ctbl'>")
                .append(HexaDecimal.encode((byte[])session.getAttribute(WalletCore.ATTR_LOGIN_DATA)))
                .append("</div>" +

                        "<div class='ctblh'>FIDO ")
                .append(KeyAlgorithms.getKeyAlgorithm(CBORPublicKey.convert(publicKey)).getKeyType())
                .append(
                        " Public Key (COSE)</div>" +
                        "<div class='ctbl'>")
                .append(HTML.encode(publicKey.toString(), true))
                .append("</div>" +

                    "</div>");
            
            // In our case we have no application using the authentication...
            session.invalidate();

            HTML.standardPage(response, Actors.ISSUER, WalletCore.GO_HOME_JAVASCRIPT, html);
        } catch (Exception e) {
            HTML.errorPage(response, e);
        }
    }
}
