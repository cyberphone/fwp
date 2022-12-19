package org.webpki.fwp;

import java.io.File;

import java.util.ArrayList;
import java.util.LinkedHashMap;

import org.webpki.util.ArrayUtil;
import org.webpki.util.HexaDecimal;

import org.webpki.cbor.CBORCryptoConstants;

public class CryptoDocument  {
    
    static final String DOC_GEN_DIRECTORY   = "docgen";
    
    static final String TEST_DATA_DIRECTORY = "testdata";

    static final String FWP_CRYPTO_SVG      = "fwp-crypto.svg";

    static final String WEB_AUTHN           = "webauthn";

    static final String TOC                 = "table-of-contents";
    
    static final String SIGNATURE_JWK       = "signature.jwk";

    static final String ENCRYPTION_JWK      = "encryption.jwk";

    static final String PAYMENT_CRED        = "paymentcred";

    static final String FWP_ASSERTIONS      = "fwpassertions";

    static final String AUTHORIZATION_DATA  = "authorizationdata";
    
    String buildDirectory;
    
    String template;
    
    static char delimiter = '@';
    
    static class Decorator {
        int[] mapEntry;
        String text;
        
        Decorator(int[] mapEntry, String text) {
            this.mapEntry = mapEntry;
            this.text = text;
        }
    }

    static LinkedHashMap<String, ArrayList<Decorator>> decoratorList = new LinkedHashMap<>();
    
    static class DecoratorBuilder {
        
        String fileName;
        
        DecoratorBuilder(String fileName) {
            this.fileName = fileName;
        }
        
        DecoratorBuilder add(int[] mapEntry, String text) {
            ArrayList<Decorator> entry = decoratorList.get(fileName);
            if (entry == null) {
                entry = new ArrayList<>();
                decoratorList.put(fileName, entry);
            }
            entry.add(new Decorator(mapEntry, text));
            return this;
        }
    }
    
    static class Toc {
        
        int level;
        int subLevel;
        String line;
        String extId;

        Toc(int level, int subLevel, String line) {
            this.level = level;
            this.subLevel = subLevel;
            this.line = line;
        }
        
        String coreId() {
            return extId == null ? 
                    String.valueOf(level) + (subLevel == 0 ? "" : "." + subLevel)
                                 :
                   extId;
        }
        
    }

    static class TocRef {
        String name;
        Toc toc;
        
    }

    static ArrayList<TocRef> links = new ArrayList<>();
    
    static ArrayList<Toc> tocs = new ArrayList<>();
    
    static class TocBuilder {
        int level;
        int subLevel;
        
        private void addInternal(String line) {
            tocs.add(new Toc(level, subLevel, line));
        }
        
        TocBuilder add(String tocLine) {
            subLevel = 0;
            level++;
            addInternal(tocLine);
            return this;
        }
        
        TocBuilder addSub(String subLine) {
            subLevel++;
            addInternal(subLine);
            return this;
        }

        TocBuilder add(String id, String line) {
            Toc toc = new Toc(0, 0, line);
            toc.extId = id;
            tocs.add(toc);
            return this;
        }
        
        TocBuilder reference(String name) {
            TocRef tocRef = new TocRef();
            tocRef.toc = tocs.get(tocs.size() - 1);
            tocRef.name = name;
            links.add(tocRef);
            return this;
        }
    }
    
    static {
        new TocBuilder()
            .add("Introduction")
            .add("Relationship to Existing Standards")
            .add("Terminology")
            .add("User Authorization")
            .addSub("Create Authorization Data (AD)")
            .reference("AD")
            .addSub("Create Signed Authorization Data (SAD)")
            .reference("SAD")
            .addSub("Signature Algorithms")
            .reference("Signature Algorithms")
            .add("Encrypted User Authorization (ESAD)")
            .reference("Encrypted User Authorization (ESAD)")
            .reference("ESAD")
            .addSub("Encryption Object")
            .addSub("Encryption Process")
            .addSub("Content Encryption Algorithms")
            .reference("Content Encryption Algorithms")
            .addSub("Key Algorithms")
            .addSub("Key Encryption Algorithms")
            .reference("Key Encryption Algorithms")
            .addSub("Key Derivation Function")
            .reference("KDF")
            .add("User Authorization Decoding and Verification")
            .addSub("Decrypt Authorization (ESAD)")
            .addSub("Decode Signed Authorization Data (SAD)")
            .addSub("Validate Signature")
            .add("Sample Keys")
            .reference("Sample Keys")
            .addSub("Signature Key")
            .addSub("Encryption Key")
            .add("documenthistory", "Document History")
            .add("authors", "Authors")
            .add("trademarks", "Trademarks");
    }

    static DecoratorBuilder addList(String fileName) {
        return new DecoratorBuilder(fileName)
            .add(new int[] {-1}, "authorization")
            .add(new int[] {-1, 1}, "signatureAlgorithm = ES256")
            .add(new int[] {-1, 2}, "publicKey")
            .add(new int[] {-1, 2, 1}, "kty = EC")
            .add(new int[] {-1, 2, -1}, "crv = P-256")
            .add(new int[] {-1, 2, -2}, "x")
            .add(new int[] {-1, 2, -3}, "y");
    }
    
    static {
        try {
            addList("AD.txt");
            addList("SAD.txt")
                .add(new int[] {-1, 3}, "authenticatorData")
                .add(new int[] {-1, 4}, "signature");
            
            int keyEncryption = CBORCryptoConstants.KEY_ENCRYPTION_LABEL.getInt();
            int ephemeralKey = CBORCryptoConstants.EPHEMERAL_KEY_LABEL.getInt();
        
            new DecoratorBuilder("ESAD.txt")
                .add(new int[] {CBORCryptoConstants.ALGORITHM_LABEL.getInt()}, "algorithm = A256GCM")
                .add(new int[] {keyEncryption}, "keyEncryption")
                .add(new int[] {keyEncryption, CBORCryptoConstants.ALGORITHM_LABEL.getInt()}, "algorithm = ECDH-ES+A256KW")
                .add(new int[] {keyEncryption, CBORCryptoConstants.KEY_ID_LABEL.getInt()}, "keyId")
                .add(new int[] {keyEncryption, ephemeralKey}, "ephemeralKey")
                .add(new int[] {keyEncryption, ephemeralKey, CBORCryptoConstants.COSE_KTY_LABEL.getInt()}, "kty = OKP")
                .add(new int[] {keyEncryption, ephemeralKey, CBORCryptoConstants.COSE_OKP_CRV_LABEL.getInt()}, "crv = X25519")
                .add(new int[] {keyEncryption, ephemeralKey, CBORCryptoConstants.COSE_OKP_X_LABEL.getInt()}, "x")
                .add(new int[] {keyEncryption, CBORCryptoConstants.CIPHER_TEXT_LABEL.getInt()}, "cipherText")
                .add(new int[] {CBORCryptoConstants.TAG_LABEL.getInt()}, "tag")
                .add(new int[] {CBORCryptoConstants.IV_LABEL.getInt()}, "iv")
                .add(new int[] {CBORCryptoConstants.CIPHER_TEXT_LABEL.getInt()}, "cipherText");
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
    
    String processCodeTxt(String string) throws Exception {
        StringBuilder buf = new StringBuilder();
        for (char c : string.toCharArray()) {
            switch (c) {
            case '\n':
                buf.append("<br>");
                break;
            case '<':
                buf.append("&lt;");
                break;
            case '>':
                buf.append("&gt;");
                break;
            case '&':
                buf.append("&amp;");
                break;
            case '\"':
                buf.append("&quot;");
                break;
            case '\'':
                buf.append("&#039;");
                break;
            case ' ':
                buf.append("&nbsp;");
                break;
            default:
                buf.append(c);
                break;
            }
        }
        return buf.toString();
    }
    
    byte[] readBinaryFile(String path) throws Exception {
        return ArrayUtil.readFile(buildDirectory + File.separator + path);
    }
    
    String readStringFile(String path) throws Exception {
        return new String(readBinaryFile(path), "utf-8");
    }
    
    String pattern(String tagAndFile) {
        return delimiter + tagAndFile + delimiter;
    }
    
    int getTag(String tagAndFile) {
        int i = template.indexOf(pattern(tagAndFile));
        if (i < 0) {
            throw new RuntimeException("Tag missing: " + pattern(tagAndFile));
        }
        return i;
    }
    
    void replace(String tagAndFile, String string) {
        getTag(tagAndFile);
        template = template.replace(pattern(tagAndFile), string);
    }
    
    String decorate(String path, String fileName) throws Exception {
        String string = processCodeTxt(readStringFile(path + File.separator + fileName));
        ArrayList<Decorator> decorators = decoratorList.get(fileName);
        if (decorators == null) {
            throw new RuntimeException("Missing decorator:" + fileName);
        }
        for (Decorator decorator : decorators) {
            int level = 0;
            int pos = -1;
            for (int number : decorator.mapEntry) {
                String find = "<br>";
                level += 2;
                for (int q = 0; q < level; q++) {
                    find += "&nbsp;";
                }
                find += number + ":";
                pos = string.indexOf(find, ++pos);
                if (pos < 0) {
                    throw new RuntimeException("Find not:" + find);
                }
            }
            String offset = "<br><div style='height:0.5em'></div>";
            while (--level >= 0) {
                offset += "&nbsp;";
            }
            string = string.substring(0, pos) + offset + 
                    "<span style='color:grey'>/ " + decorator.text + 
                    " /</span>" + string.substring(pos);
        }
        return string;
    }

    String generateToc() {
        StringBuilder toc = new StringBuilder();
        for (Toc tocEntry : tocs) {
            String nr = tocEntry.coreId();
            String id = tocEntry.extId;
            String tocIndex = "";
            String entryIndex = "";
            if (id == null) {
                id = nr;
                tocIndex = nr + " ";
                entryIndex = nr + ". ";
            }
            toc.append("<div class='toc'>")
               .append(tocEntry.subLevel == 0 ? "" : "&nbsp;&nbsp;&nbsp;&nbsp;")
               .append("<a href='#")
               .append(id)
               .append("'>")
               .append(tocIndex)
               .append(tocEntry.line)
               .append("</a></div>");
            replace(tocEntry.line, "<div id='" + id + 
                    (tocEntry.subLevel == 0 ? "' class='header'>" : "' class='subheader'>") + 
                    entryIndex + tocEntry.line + "</div>");
        }
        return toc.toString();
    }
    
    void generateLinks() {
        for (TocRef tocRef : links) {
            replace(tocRef.name, "<a href='#" + tocRef.toc.coreId()+ "'>" + tocRef.name + "</a>");
        }
        
    }
    
    void process(String[] tagAndFiles) throws Exception {
        for (String tagAndFile : tagAndFiles) {
            getTag(tagAndFile);
            String fileName = tagAndFile.substring(4);
            if (tagAndFile.startsWith("hex/")) {
                replace(tagAndFile, HexaDecimal.encode(
                        readBinaryFile(TEST_DATA_DIRECTORY + File.separator + fileName)));
            } else if (tagAndFile.startsWith("txt/")) {
                replace(tagAndFile, decorate("testdata", fileName));
            } else {
                throw new RuntimeException("unrec: " + tagAndFile);
            }
        }
    }
    
    void textFile(String name) throws Exception {
        replace(name, processCodeTxt(readStringFile(
                TEST_DATA_DIRECTORY + File.separator + name)));
    }

    CryptoDocument (String buildDirectory, String resultFile) throws Exception {
        this.buildDirectory = buildDirectory;
        this.template =  readStringFile(DOC_GEN_DIRECTORY + File.separator + "crypto-template.html");
        process(new String[]{"hex/ad.cbor", 
                             "txt/AD.txt",
                             "hex/sad.cbor", 
                             "txt/SAD.txt",
                             "hex/esad.cbor",
                             "txt/ESAD.txt"});

        String svg =  readStringFile(DOC_GEN_DIRECTORY + File.separator + FWP_CRYPTO_SVG);
        svg = "<svg style='display:block;width:27em;padding:1em' class='box' " + 
                          svg.substring(svg.indexOf("<svg ") + 5);
        replace(FWP_CRYPTO_SVG, svg);
        replace(WEB_AUTHN, "<a href='https://www.w3.org/TR/webauthn-2/' " +
                            "title='Web Authentication'>" +
                            "Web&nbsp;Authentication<img src='images/xtl.svg' alt='link'></a>");
        replace(PAYMENT_CRED, "<a href='index.html#credentialdatabase'>" +
                              "Payment Credential<img src='images/xtl.svg' alt='link'></a>");
        replace(FWP_ASSERTIONS, "<a href='index.html#seq-4.5'>" +
                "FWP Assertions<img src='images/xtl.svg' alt='link'></a>");
        replace(AUTHORIZATION_DATA, "<a href='index.html#seq-4.2'>" +
                "Authorization Data (AD)<img src='images/xtl.svg' alt='link'></a>");

        replace(TOC, generateToc());
        
        textFile(SIGNATURE_JWK);
        textFile(ENCRYPTION_JWK);

        delimiter = '#';

        generateLinks();
        
        ArrayUtil.writeFile(resultFile, template.getBytes("utf-8"));
    }

    public static void main(String[] argc) {
        try {
            new CryptoDocument(argc[0], argc[1]);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
