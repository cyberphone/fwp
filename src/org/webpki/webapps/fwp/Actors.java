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

public enum Actors {
    
    SITE     (
        "<div style='display:flex;padding-bottom:10pt'>" +
        "<a href='https://github.com/cyberphone/fwp' target='_blank'><img src='images/fwp.svg' " +
        "style='height:25pt' " +
        "title='Specifications, source code, etc.'/></a>"),
    FWP      (
        "<div style='display:flex;padding-bottom:10pt'>" +
        "<img src='images/wallet-internal.svg' " +
        "style='height:35pt' " +
        "title='Wallet Internal Operation'/>"),
    WALLET   (
            "<div style='display:flex;padding-bottom:10pt'>" +
            "<img src='images/wallet-ui.svg' " +
            "style='height:35pt' " +
            "title='Wallet UI'/>"),
    MERCHANT (
        "<div style='display:flex;padding-bottom:10pt'>" +
        "<img src='images/merchant.svg' " +
        "style='height:35pt' " +
        "title='Merchant'/>"),
    PSP      (
        "<div style='display:flex;padding-bottom:10pt'>" +
        "<img src='images/psp.svg' " +
        "style='height:35pt' " +
        "title='Payment System Provider'/>"),
    ISSUER   (
            "<div style='display:flex;padding-bottom:10pt'>" +
            "<img src='images/issuer.svg' " +
            "style='height:35pt' " +
            "title='Issuer (bank)'/>"),
    ADMIN    (
        "<div style='display:flex;padding-bottom:10pt'>" +
        "<img src='../images/issuer.svg' " +
        "style='height:35pt' " +
        "title='Administrator'/>");
    
    String html;

    Actors(String html) {
        this.html = html;
    }

}
