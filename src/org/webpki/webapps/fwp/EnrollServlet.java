/*
 *  Copyright 2018-2020 WebPKI.org (http://webpki.org).
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
            boolean alreadyEnrolled = FWPCommon.hasPaymentCards(request);
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
                      "In a real-world setting, you would enroll cards at an <i>issuer</i> site " +
                      "(after having logged-in using an <i>issuer-specific method</i>)." +
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
                    "<div class='stdbtn' onclick=\"startEnroll()\">" +
                      "Start Enrollment!" +
                    "</div>" +
                  "</div>" +
                "</div>" +
                
                "</form>");
    
            String js = alreadyEnrolled ? null : new StringBuilder(
                "'use strict';\n" +
                
                "let globalError = null;\n" +

                FWPCommon.FWP_JAVASCRIPT +

                "function setError(message) {\n" +
                "  if (!globalError) {\n" +
                "    console.log('Fail: ' + message);\n" +
                "    globalError = message;\n" +
                "    document.getElementById('" + WAITING_ID + "').style.display = 'none';\n" +
                "    let e = document.getElementById('" + FAILED_ID + "');\n" +
                "    e.textContent = 'Fail: ' + globalError;\n" +
                "    e.style.display = 'block';\n" +
                "  }\n" +
                "}\n" +
                
                "async function startEnroll() {\n" +
                "  document.getElementById('" + USER_IFC_ID + "').style.display = 'none';\n" +
                "  document.getElementById('" + WAITING_ID + "').style.display = 'block';\n" +
                "  const initPhase = await exchangeJSON({},'" + FWPCommon.INIT_PHASE + "');\n" +
                "  if (globalError) return;\n" +
    
                "  let userId = initPhase." + FWPCommon.RP_USER_ID + ";\n" +
                "  let publicKey = {\n" +
                "    challenge: b64urlToU8arr(initPhase." + FWPCommon.RP_CHALLENGE_JSON + "),\n" +
                "    rp: {\n" +
                "      name: 'FIDO Web Pay'\n" +
                "    },\n" +
                "    user: {\n" +
                "      id: new TextEncoder().encode(userId),\n" +
                "      name: userId,\n" +
                "      displayName: 'FWP User'\n" +
                "    },\n" +
                "    pubKeyCredParams: [{\n" +
                "      type: 'public-key',\n" +
                "      alg: -7\n" +
                "    },{\n" +
                "      type: 'public-key',\n" +
                "      alg: -8\n" +
                "    },{\n" +
                "      type: 'public-key',\n" +
                "      alg: -257\n" +
                "    }],\n" +
                "    timeout: 360000,\n" +
                "    excludeCredentials: [],\n" +
                "    authenticatorSelection: {\n" +
                "      residentKey: 'preferred',\n" +
                "      userVerification: 'preferred'\n" +
                "    },\n" +
                "    attestation: 'direct',\n" +
                "    extensions: {}\n" +
                "  };\n" +
                
                "  console.log(publicKey);\n" +
                "  try {\n" +
                "    const result = await navigator.credentials.create({publicKey});\n" +
                "    console.log(result);\n" +
                "    const finalizePhase = await exchangeJSON({" + 

                         FWPCommon.CARD_HOLDER_JSON + ":" +
                         "document.getElementById('" + CARD_HOLDER_NAME + "').value," +

                         FWPCommon.KEY_HANDLE_JSON + ":result.id," +

                         FWPCommon.ATTESTATION_JSON + 
                         ":arrBufToB64url(result.response.attestationObject)," +

                         FWPCommon.CLIENT_DATA_JSON + 
                         ":arrBufToB64url(result.response.clientDataJSON)},'" +

                         FWPCommon.FINALIZE_PHASE + "');\n" +

                "    if (!globalError) document.forms.shoot.submit();\n" +

                "  } catch (error) {\n" +
                "    setError(error);\n" +
                "  }\n" +
                
                "}\n").toString();
            HTML.standardPage(response, js, html);
        } catch (Exception e) {
            HTML.errorPage(response, e);
        }
    }
    
    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {
        try {
            StringBuilder html = new StringBuilder(
                "<div class='header'>Enrollment Succeeded</div>" +

                "<div style='display:flex;justify-content:center;margin-top:15pt'>" +
                    "You did it!" +
                "</div>" +

                "<div style='display:flex;justify-content:center'>" +
                  "<div class='stdbtn' onclick=\"document.location.href='hash'\">" +
                      "Buy Something..." +
                  "</div>" +
                "</div>");
            HTML.standardPage(response, null, html);
        } catch (Exception e) {
            HTML.errorPage(response, e);
        }
    }
}
