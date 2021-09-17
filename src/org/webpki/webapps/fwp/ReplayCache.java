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
 * Singleton thread dealing with a reply cache.
 * 
 * Replays are only checked within the time limits for
 * authorizations, because if an authorization is too old, it
 * will be immediately rejected anyway, and not go into the cache.
 * 
 */
public enum ReplayCache {

    // Single-element enums are according to many Java gurus the optimal
    // way creating thread-safe singletons.
    INSTANCE;

    static final long CYCLE_TIME = 120000;

    Logger logger = Logger.getLogger(ReplayCache.class.getCanonicalName());

    final ConcurrentHashMap<ByteBuffer, Long> cache = new ConcurrentHashMap<>();

    ReplayCache() {
        new Thread(new Runnable() {

            @Override
            public void run() {
                while (true) {
                    try {
                        Thread.sleep(CYCLE_TIME);
                        long now = System.currentTimeMillis();
                        cache.forEach((cacheableSadObject, expirationTime) -> {
                            if (expirationTime < now) {
                                // This authorization is already consumed but is now too 
                                // old to qualify, so we can safely remove it from the cache
                                // (in order to keep it as small and up-to-date as possible).
                                cache.remove(cacheableSadObject);
                                logger.info("Removed authorization token: " + 
                                            cacheableSadObject.hashCode());
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
     * @param cacheableSadObject The SAD object packaged to suit HashMap
     * @param expirationTime For the SAD object
     * @return <code>true</code> if replay, else <code>false</code>
     */
    public boolean add(ByteBuffer cacheableSadObject, long expirationTime) {
        return cache.putIfAbsent(cacheableSadObject, expirationTime) != null;
    }
}
