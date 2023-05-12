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

import org.webpki.cbor.CBORInt;

/**
 * Core elements of an FWP assertion.
 * 
 */
public enum FWPElements {
    
    PAYMENT_REQUEST           (1),
    PAYEE_HOST                (2),
    ACCOUNT_ID                (3),
    PAYMENT_NETWORK_ID        (4),
    SERIAL_NUMBER             (5),
    NETWORK_OPTIONS           (6),  // Optional (Merchant)
    PLATFORM_DATA             (7), 
    LOCATION                  (8),  // Optional (Client)
    TIME_STAMP                (9),
    AUTHORIZATION             (-1);
    
    
    CBORInt cborLabel;

    FWPElements(int cborLabel) {
        this.cborLabel = new CBORInt(cborLabel);
    }
    
    // Platform Data
    public static final CBORInt CBOR_PD_OPERATING_SYSTEM = new CBORInt(1);
    public static final CBORInt CBOR_PD_USER_AGENT       = new CBORInt(2);

    // Platform Data sub elements
    public static final CBORInt CBOR_PDSUB_NAME          = new CBORInt(3);
    public static final CBORInt CBOR_PDSUB_VERSION       = new CBORInt(4);
    
}
    
