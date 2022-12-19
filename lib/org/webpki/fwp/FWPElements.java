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
package org.webpki.fwp;

import org.webpki.cbor.CBORInteger;

/**
 * Core elements of an FWP assertion.
 * 
 */
public enum FWPElements {
    
    FWP_VERSION               (1),
    PAYMENT_REQUEST           (2),
    PAYEE_HOST                (3),
    ACCOUNT_ID                (4),
    PAYMENT_NETWORK_ID        (5),
    SERIAL_NUMBER             (6),
    NETWORK_OPTIONS           (7),
    PLATFORM_DATA             (8),
    TIME_STAMP                (9),
    AUTHORIZATION             (-1);
    
    
    CBORInteger cborLabel;

    FWPElements(int cborLabel) {
        this.cborLabel = new CBORInteger(cborLabel);
    }
    
    public static final String CURRENT_VERSION = "1.0";
    
    // Platform Data
    public static final CBORInteger CBOR_PD_OPERATING_SYSTEM = new CBORInteger(1);
    public static final CBORInteger CBOR_PD_USER_AGENT       = new CBORInteger(2);

    // Platform Data sub elements
    public static final CBORInteger CBOR_PDSUB_NAME          = new CBORInteger(3);
    public static final CBORInteger CBOR_PDSUB_VERSION       = new CBORInteger(4);
    
}
    
