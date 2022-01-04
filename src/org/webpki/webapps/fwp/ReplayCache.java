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

import java.nio.ByteBuffer;

import java.util.concurrent.ConcurrentHashMap;

import java.util.logging.Logger;

/**
 * Reply cache support.
 * 
 * Replays are only checked within the time limits for authorizations, because 
 * if a received authorization has already expired, it should be rejected,
 * rather than being cached.
 * 
 */
public enum ReplayCache {

    // According to multiple Java information resources, the "enum" type represents
    // a viable option for creating singletons in multi-threaded applications.
    INSTANCE;

    private Logger logger = Logger.getLogger(ReplayCache.class.getName());

    private final ConcurrentHashMap<ByteBuffer, Long> cache = new ConcurrentHashMap<>();

    private ReplayCache() {
        new Thread(new Runnable() {

            @Override
            public void run() {
                while (true) {
                    try {
                        Thread.sleep(IssuerServlet.AUTHORIZATION_MAX_AGE / 5);
                        long now = System.currentTimeMillis();
                        cache.forEach((hashableSadObject, expirationTime) -> {
                            if (expirationTime < now) {
                                // The authorization has apparently expired so we can safely
                                // remove it from the replay cache in order to keep the cache
                                // as small and up-to-date as possible.
                                cache.remove(hashableSadObject);
                                logger.info("Removed authorization token: " + 
                                            hashableSadObject.hashCode());
                            }
                        });
                    } catch (InterruptedException e) {
                        new RuntimeException("Unexpected interrupt", e);
                    }
                }
            }
           
        }).start();
    }
    
    /**
     * Add validated SAD object to the replay cache.
     *
     * Note: the <code>expirationTime</code> stays the same for replayed SAD objects,
     * making rewrites benign.
     * 
     * @param hashableSadObject The SAD object packaged to suit HashMap
     * @param expirationTime For the SAD object
     * @return <code>true</code> if replay, else <code>false</code>
     */
    public boolean add(ByteBuffer hashableSadObject, long expirationTime) {
        return cache.put(hashableSadObject, expirationTime) != null;
    }
}
