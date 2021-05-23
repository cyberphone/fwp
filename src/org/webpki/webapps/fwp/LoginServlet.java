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

import org.webpki.cbor.CBORPublicKey;

/**
 * This is just for testing enrolled credentials
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
                  "Login is not a part of FIDO Web Pay, but associated FIDO authenticators " +
                  "can <i>optionally</i> be used for that as well." +
              "</div>" +
            "</div>" +
            
            "<div style='display:flex;justify-content:center'>" +
              "<img id='" + WAITING_ID + "' src='images/waiting.gif' " +
                  "style='padding-top:2em;display:none' alt='waiting'/>" +
            "</div>" +

            "<div id='" + FAILED_ID + "' class='errorText'></div>" +

            "<div style='display:flex;justify-content:center'>" +
              "<div id='" + ACTIVATE_ID + "' class='stdbtn' onclick=\"startLogin()\">" +
                "Login..." +
              "</div>" +
            "</div>" +
            "</form>");

        String js = new StringBuilder(
            "'use strict';\n" +
            
            "let globalError = null;\n" +
            
            "const serviceUrl = 'fidologin';\n" +

            FWPCommon.FWP_JAVASCRIPT +

            "function setError(message) {\n" +
            "  if (!globalError) {\n" +
            "    console.log('Fail: ' + globalError);\n" +
            "    globalError = message;\n" +
            "    let e = document.getElementById('" + FAILED_ID + "');\n" +
            "    e.textContent = 'Fail: ' + globalError;\n" +
            "    e.style.display = 'block';\n" +
            "  }\n" +
            "}\n" +
            
            "async function startLogin() {\n" +
            "  document.getElementById('" + ACTIVATE_ID + "').style.display = 'none';\n" +
            "  document.getElementById('" + WAITING_ID + "').style.display = 'block';\n" +
            "  const initPhase = await exchangeJSON({},'" + FWPCommon.INIT_PHASE + "');\n" +
            "  if (globalError) return;\n" +

            "  const options = {\n" +
            "    challenge: b64urlToU8arr(initPhase." + FWPCommon.CHALLENGE + "),\n" +

            "    allowCredentials: [{type: 'public-key', " +
                     "id: b64urlToU8arr(initPhase." + FWPCommon.CREDENTIAL_ID + ")}],\n" +

            "    userVerification: 'preferred',\n" +

            "    timeout: 120000\n" +
            "  };\n" +
            
//            "  console.log(options);\n" +
            "  try {\n" +
            "    const result = await navigator.credentials.get({ publicKey: options });\n" +
//            "    console.log(result);\n" +
            "    const finalizePhase = await exchangeJSON({" + 

                         FWPCommon.AUTHENTICATOR_DATA_JSON + 
                         ":arrBufToB64url(result.response.authenticatorData)," +

                         FWPCommon.SIGNATURE_JSON + 
                         ":arrBufToB64url(result.response.signature)," +

                         FWPCommon.CLIENT_DATA_JSON + 
                         ":arrBufToB64url(result.response.clientDataJSON)},'" +

                         FWPCommon.FINALIZE_PHASE + "');\n" +

            "    if (!globalError) document.forms.shoot.submit();\n" +

            "  } catch (error) {\n" +
            "    setError(error);\n" +
            "  }\n" +

            "}\n").toString();
        HTML.standardPage(response, js, html);
    }
    
    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {
        try {
            // Get the enrolled user.
            String userId = FWPCommon.getWalletCookie(request);
            if (userId == null) {
                FWPCommon.failed("User ID missing, have you enrolled?");
            }
            
            // Lookup in database
            DataBaseOperations.CoreClientData coreClientData;
            try (Connection connection = FWPService.jdbcDataSource.getConnection();) {
                // Get the anticipated public key
                coreClientData = DataBaseOperations.getCoreClientData(userId, connection);
            }
            
            HttpSession session = request.getSession();
            
            StringBuilder html = new StringBuilder(
                    "<div class='header'>Login Succeeded!</div>" +
            
                    "<div style='display:flex;justify-content:center;margin-top:15pt'>" +
                      "<div class='comment'>" +
                         "This is what the login returned from the user database." +
                      "</div>" +
                    "</div>" +

                    "<div style='display:flex;justify-content:center;margin-top:15pt'>" +
                      "<table class='codetable'>" +

                        "<tr><th>Card Holder</th></tr>" +
                        "<tr><td style='text-align:center;font-family:Roboto,sans-serif,Segoe UI'>")
                .append(coreClientData.cardHolder)
                .append("</td></tr>" +

                        "<tr><th>User ID</th></tr>" +
                        "<tr><td style='text-align:center'><code>")
                .append(userId)
                .append("</code></td></tr>" +
                
                        "<tr><th>Web Session ID</th></tr>" +
                        "<tr><td style='text-align:center'><code>")
                .append(session.getId())
                .append("</code></td></tr>" +
                
                        "<tr><th>FIDO Credential ID (B64U)</th></tr>" +
                        "<tr><td style='text-align:center'><code>")
                .append(coreClientData.credentialId)
                .append("</code></td></tr>" +

                        "<tr><th>FIDO Public Key (COSE)</th></tr>" +
                        "<tr><td style='word-break:break-all;text-align:left'><code>")
                .append(CBORPublicKey.encode(coreClientData.publicKey).toString()
                            .replace("\n", "<br>").replace(" ", "&nbsp;"))
                .append("</code></td></tr>" +

                        "</table>" +
                    "</div>");
            
            // In our case we have no application using the authentication...
            session.invalidate();

            HTML.standardPage(response, null, html);
        } catch (Exception e) {
            HTML.errorPage(response, e);
        }
    }
}
