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

/**
 * This is just for testing enrolled credentials
 *
 */
public class LoginServlet extends HttpServlet {
    
    static Logger logger = Logger.getLogger(LoginServlet.class.getName());

    private static final long serialVersionUID = 1L;
    
    
    private static final String FAILED_ID  = "fail";

    
    public void doGet(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {
        StringBuilder html = new StringBuilder(
            "<form name='shoot' method='POST' action='login'>" +

            "<div class='header'>Login Test</div>" +

            "<div id='" + FAILED_ID + "' class='errorText'></div>" +
            "<div style='display:flex;justify-content:center'>" +
              "<div class='stdbtn' onclick=\"startLogin()\">" +
                "Login..." +
              "</div>" +
            "</div>" +
            "</form>");

        String js = new StringBuilder(
            "'use strict';\n" +
            
            "let globalError = null;\n" +
            
            "const serviceUrl = 'fidologin';\n" +

            FWPCommon.FWP_JAVASCRIPT +

            "function b64urlToU8arr(code) {\n" +
            "  return Uint8Array.from(window.atob(" +
                   "code.replace(/-/g, '+').replace(/_/g, '/')), c=>c.charCodeAt(0));\n" +
            "}\n" +

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
            "  const initPhase = await exchangeJSON({},'" + FWPCommon.INIT_PHASE + "');\n" +
            "  if (globalError) return;\n" +

            "  const options = {\n" +
            "    challenge: b64urlToU8arr(initPhase." + FWPCommon.CHALLENGE + "),\n" +

            "    allowCredentials: [{type: 'public-key', " +
                     "id: b64urlToU8arr(initPhase." + FWPCommon.CREDENTIAL_ID + ")}],\n" +

            "    userVerification: 'preferred'," +

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
        StringBuilder html = new StringBuilder(
            "<div class='header'>Login Succeeded</div>" +

            "<div style='display:flex;justify-content:center;margin-top:15pt'>" +
                "You did it!" +
            "</div>");
        HTML.standardPage(response, null, html);
    }
}
