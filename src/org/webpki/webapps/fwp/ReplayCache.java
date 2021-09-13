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

import java.util.concurrent.ConcurrentHashMap;

import java.util.function.BiConsumer;

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

    final ConcurrentHashMap<String, Long> cache = new ConcurrentHashMap<>();

    ReplayCache() {
        new Thread(new Runnable() {

            @Override
            public void run() {
                while (true) {
                    try {
                        Thread.sleep(CYCLE_TIME);
                        long now = System.currentTimeMillis();
                        cache.forEach(new BiConsumer<String, Long>() {

                            @Override
                            public void accept(String hashedAuthorizationB64U,
                                               Long payerTimeStampOldest) {
                                if (payerTimeStampOldest < now) {
                                    // This authorization is already consumed but is now
                                    // too old to qualify, so we remove it from the cache.
                                    cache.remove(hashedAuthorizationB64U);
                                    logger.info("removed token: " + hashedAuthorizationB64U);
                                }
                            }

                        });
                    } catch (InterruptedException e) {
                        e.printStackTrace();
                        return;
                    }
                }
            }
           
        }).start();
    }
    
    public boolean add(String hashedAuthorizationB64U, long payerTimeStampOldest) {
        boolean replay = cache.put(hashedAuthorizationB64U, payerTimeStampOldest) != null;
        if (replay) {
            logger.info("Replay of token: " + hashedAuthorizationB64U);
        }
        return replay;
    }
}
