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

/**
 * This is not a part of a serious solution...
 *
 */
public class SystemDetection {
    
    String operatingSystemName = "Unknown";
    String operatingSystemVersion = "N/A";
    String browserName = "Unknown";
    String browserVersion = "N/A";
    
    SystemDetection(String userAgent) {
        if (userAgent == null) {
            return;
        }
        if (userAgent.contains("Android")) {
            operatingSystemName = "Android";
        } else if (userAgent.contains("Win")) {
            operatingSystemName = "Windows";
        } else if (userAgent.contains("Linux")) {
            operatingSystemName = "Linux";
        } else if (userAgent.contains("iPhone")) {
            operatingSystemName = "iOS";
        } else if (userAgent.contains("iPad")) {
            operatingSystemName = "iOS";
        } else if (userAgent.contains("Mac OS")) {
            operatingSystemName = "Mac OS";
        }
        String versionFix = null;
        if (userAgent.contains("Edg/")) {
            browserName = "Edge";
            versionFix = " Edg";
        } else if (userAgent.contains("EdgA/")) {
            browserName = "Edge";
            versionFix = " EdgA";
        } else if (userAgent.contains("Chrome")) {
            browserName = "Chrome";
        } else if (userAgent.contains("Safari")) {
            browserName = "Safari";
            versionFix = " Version";
        } else if (userAgent.contains("Firefox")) {
            browserName = "Firefox";
        } else {
            return;
        }
        String target = versionFix == null ? browserName : versionFix;
        int i = userAgent.indexOf(target + "/");
        if (i <= 0) {
            return;
        }
        i += target.length();
        browserVersion = "";
        while (++i < userAgent.length()) {
            char c = userAgent.charAt(i);
            if (c < '0' || c > '9') {
                if (c == '.' && browserName.equals("Safari") && versionFix != null) {
                    versionFix = null;
                } else {
                    break;
                }
            }
            browserVersion += c;
         }
    }
}
