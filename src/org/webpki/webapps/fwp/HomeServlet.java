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

import javax.servlet.ServletException;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class HomeServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;

    public void doGet(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {

        HTML.standardPage(response, null, new StringBuilder(
            "<div class='header'>Fido Web Pay (FWP) Demo</div>" +
            "<div style='padding-top:15pt'>This site permits testing and debugging " +
            "a scheme for a payment authorization system based on FIDO2. " + 
            "Due to the lack of built-in browser support, the UI is " +
            "currently implemented as a Web emulator.</div>" +
            "<div style='display:flex;justify-content:center'><table>" +
            "<tr><td><div class='multibtn' " +
            "onclick=\"document.location.href='hash'\" " +
            "title='Buy Something!'>" +
            "Buy Something!" +
            "</div></td></tr>" +
            "<tr><td><div class='multibtn' " +
            "onclick=\"document.location.href='enroll'\" " +
            "title='Enroll Payment Cards'>" +
            "Enroll Payment Cards..." +
            "</div></td></tr>" +
            "<tr><td><div class='multibtn' " +
            "onclick=\"document.location.href='disenroll'\" " +
            "title='Delete Payment Cards...'>" +
            "Delete Payment Cards..." +
            "</div></td></tr>" +
            "</table></div>" +
            "<div class='sitefooter'>Privacy/security notice: this test site depends on local " +
            "but persistent cookies.</div>"));
    }
}
