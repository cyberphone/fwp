/*
 *  Copyright 2006-2021 WebPKI.org (http://webpki.org).
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

import java.io.File;

import org.webpki.cbor.CBORObject;

import static org.webpki.cbor.CBORCryptoConstants.*;

import org.webpki.util.IO;

/**
 * Make SVG images for CBOR encryption and the FWP subset
 */
public class CryptoImages {
    
    static int HEADER_HEIGHT = 150;
    
    static int MARGIN = 20;
    
    static int LABEL_GUTTER = 20;
    static int LABEL_HEIGHT = 80;
    
    static int IMAGE_WIDTH  = 83;
    
    static final int TEXT_LEFT_MARGIN = 24;
    static final int TEXT_FONT_SIZE = 40;
    static final int TEXT_Y_OFFSET = 54;
    static final int HEADER_FONT_SIZE = 50;
    static final int HEADER_Y_OFFSET = 60;
    static final int SUB_HEADER_Y_OFFSET = 110;

    boolean cborFull;
    boolean initialLabel;
    StringBuilder svg;
    StringBuilder textLabels;
    StringBuilder headerTexts;
    int left;
    int top;
    int width;
    
    int mainMapWidth() {
        return 460;
    }
    
    int subMapWidth() {
        return cborFull ? 510 : 440;
    }
    
    int totalHeight() {
        return (cborFull ? 7 * LABEL_HEIGHT + 6 * LABEL_GUTTER
                                       :
                           5 * LABEL_HEIGHT + 4 * LABEL_GUTTER) + HEADER_HEIGHT + MARGIN;
    }
    
    void label(String labelText, CBORObject cborLabel, boolean mandatory) throws Exception {
        if (!initialLabel) {
            top += LABEL_GUTTER;
        }
        initialLabel = false;
        svg.append("<rect x='")
           .append(left)
           .append("' y='")
           .append(top)
           .append("' width='")
           .append(width)
           .append("' height='" + LABEL_HEIGHT)
           .append(mandatory ? "" : "' stroke-dasharray='8")
           .append("' rx='8'/>\n");

        textLabels.append("<text x='")
                  .append(left + TEXT_LEFT_MARGIN)
                  .append("' y='")
                  .append(top + TEXT_Y_OFFSET)
                  .append("'>")
                  .append(labelText)
                  .append("<tspan fill='black'> (")
                  .append(cborLabel.getInt32())
                  .append(")</tspan></text>\n");
        
        top += LABEL_HEIGHT;
    }
    
    void headers(String subHeaderText, String mainHeaderText) {
        initialLabel = true;
        headerTexts.append("<text x='")
                   .append(left + width / 2)
                   .append("' y='")
                   .append(HEADER_Y_OFFSET)
                   .append("' font-size='" + HEADER_FONT_SIZE + "' text-anchor='middle'>")
                   .append(mainHeaderText)
                   .append("</text>\n<text x='")
                   .append(left + width / 2)
                   .append("' y='")
                   .append(SUB_HEADER_Y_OFFSET)
                   .append("' text-anchor='middle'>")
                   .append(subHeaderText)
                   .append("</text>\n");     

    }
        
    void execute(String fileName, boolean cborFull) throws Exception {
        this.cborFull = cborFull;
        textLabels = new StringBuilder();
        headerTexts = new StringBuilder();
        svg = new StringBuilder(
                "<?xml version='1.0' encoding='utf-8'?>\n" +
                "<svg viewBox='0 0 ")
            .append(mainMapWidth() + subMapWidth() + IMAGE_WIDTH + 4 * MARGIN)
            .append(' ')
            .append(totalHeight())
            .append("' xmlns='http://www.w3.org/2000/svg'>\n" + 
                "<title>")
            .append(cborFull ? "CBOR Encryption Format" : "FWP Encryption Layout")
            .append(
                 "</title>\n<!-- Anders Rundgren 2021 -->\n" +
                 "<g stroke='#4366bf' stroke-width='3' fill='none'>\n");
        top = HEADER_HEIGHT;
        left = MARGIN;
        width = mainMapWidth();

        headers("(Content Encryption)", "Main Map");

        if (cborFull) {
            label("customData", CXF_CUSTOM_DATA_LBL, false);
        }
        label("algorithm", CXF_ALGORITHM_LBL, true);
        label("keyEncryption", CEF_KEY_ENCRYPTION_LBL, !cborFull);
        if (cborFull) {
            label("keyId", CXF_KEY_ID_LBL, false);
        }        
        label("tag", CEF_TAG_LBL, true);
        label("iv", CEF_IV_LBL, true);
        label("cipherText", CEF_CIPHER_TEXT_LBL, true);
        
        top = HEADER_HEIGHT;
        left += width + IMAGE_WIDTH + 2 * MARGIN;
        width = subMapWidth();

        headers("(Key Encryption)", cborFull ? "Optional Sub Map" : "Sub Map");

        label("algorithm", CXF_ALGORITHM_LBL, true);
        label("keyId", CXF_KEY_ID_LBL, false);
        label("publicKey", CXF_PUBLIC_KEY_LBL, false);
        if (cborFull) {
            label("certificatePath", CXF_CERT_PATH_LBL, false);
        }
        label("ephemeralKey", CEF_EPHEMERAL_KEY_LBL, !cborFull);
        label("cipherText", CEF_CIPHER_TEXT_LBL, false);
        
        int lowerPath = (LABEL_HEIGHT + LABEL_GUTTER) * 2;
        int upperPath = cborFull ? (LABEL_GUTTER + LABEL_HEIGHT) : 0;
        int turnParam = (LABEL_GUTTER + LABEL_GUTTER + LABEL_HEIGHT) / 2;

        svg.append("</g>\n<g font-size='" + TEXT_FONT_SIZE + 
                   "' font-family='Roboto,sans-serif'>\n")
           .append(headerTexts)
           .append("</g>\n" +
                   "<g font-size='" + TEXT_FONT_SIZE + 
                               "' font-family='Noto Mono,monospace' fill='maroon'>\n")
           .append(textLabels)
           .append("</g>\n" +
                   "<path fill='none' stroke='#4366bf' stroke-width='3' stroke-linecap='round' d='m ")
           .append(left - MARGIN)
           .append("," + HEADER_HEIGHT)
           .append(" c -35,0 -35," + LABEL_HEIGHT + " -35," + LABEL_HEIGHT +
                   " v " + upperPath +
                   " c 0,0 0,49 -48," + turnParam + 
                   " c 48,11 48," + turnParam + " 48," + turnParam +
                   " v " + lowerPath + " c 0,0 0," + LABEL_HEIGHT + " 35," + LABEL_HEIGHT + "'/>\n");
        
        IO.writeFile(fileName, svg.append("</svg>\n").toString());
    }
    
    public CryptoImages(String buildDirectory) throws Exception {
        String directory = buildDirectory + File.separatorChar + 
                           CryptoDocument.DOC_GEN_DIRECTORY + File.separatorChar;
        execute(directory + "fwp-crypto.svg", false);
        execute(directory + "cbor-crypto.svg", true);
    }

    public static void main(String[] args) {
        try {
           new CryptoImages(args[0]);
        } catch (Exception e) {
            e.printStackTrace();
        }
        
    }
}
