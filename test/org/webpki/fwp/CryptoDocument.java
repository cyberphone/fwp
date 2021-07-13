package org.webpki.fwp;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedHashMap;

import org.webpki.util.ArrayUtil;
import org.webpki.util.DebugFormatter;

public class CryptoDocument  {
    
    static final String DOC_GEN_DIRECTORY = "docgen";

    String buildDirectory;
    
    String template;
    
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

    static DecoratorBuilder addList(String fileName) {
        return new DecoratorBuilder(fileName)
            .add(new int[] {10}, "&quot;authorization&quot;")
            .add(new int[] {10, 1}, "&quot;signatureAlgorithm&quot; = ES256")
            .add(new int[] {10, 2}, "&quot;publicKey&quot;")
            .add(new int[] {10, 2, 1}, "&quot;kty&quot; = EC")
            .add(new int[] {10, 2, -1}, "&quot;crv&quot; = P-256")
            .add(new int[] {10, 2, -2}, "&quot;x&quot;")
            .add(new int[] {10, 2, -3}, "&quot;y&quot;");
    }
    
    static {
        addList("AD.txt");
        addList("SAD.txt")
            .add(new int[] {10, 3}, "&quot;authenticatorData&quot;")
            .add(new int[] {10, 4}, "&quot;clientDataJSON&quot;")
            .add(new int[] {10, 5}, "&quot;signature&quot;");

        new DecoratorBuilder("ESAD.txt")
            .add(new int[] {1}, "&quot;algorithm&quot; = A256GCM")
            .add(new int[] {2}, "&quot;keyEncryption&quot;")
            .add(new int[] {2, 1}, "&quot;algorithm&quot; = ECDH-ES+A256KW")
            .add(new int[] {2, 3}, "&quot;keyId&quot;")
            .add(new int[] {2, 5}, "&quot;ephemeralKey&quot;")
            .add(new int[] {2, 5, 1}, "&quot;kty&quot; = OKP")
            .add(new int[] {2, 5, -1}, "&quot;crv&quot; = X25519")
            .add(new int[] {2, 5, -2}, "&quot;x&quot;")
            .add(new int[] {2, 9}, "&quot;cipherText&quot;")
            .add(new int[] {7}, "&quot;tag&quot;")
            .add(new int[] {8}, "&quot;iv&quot;")
            .add(new int[] {9}, "&quot;cipherText&quot;");
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
        return "@" + tagAndFile + "@";
    }
    
    int getTag(String tagAndFile) {
        int i = template.indexOf(pattern(tagAndFile));
        if (i < 0) {
            throw new RuntimeException("Tag missing");
        }
        return i;
    }
    
    void replace(String tagAndFile, String string) {
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
                    "<span style='color:grey'>// " + decorator.text + 
                    "</span>" + string.substring(pos);
        }
        return string;
    }
    
    void process(String[] tagAndFiles) throws Exception {
        for (String tagAndFile : tagAndFiles) {
            getTag(tagAndFile);
            String fileName = tagAndFile.substring(4);
            if (tagAndFile.startsWith("hex/")) {
                replace(tagAndFile, DebugFormatter.getHexString(
                        readBinaryFile("testdata" + File.separator + fileName)));
            } else if (tagAndFile.startsWith("txt/")) {
                replace(tagAndFile, decorate("testdata", fileName));
            } else {
                throw new RuntimeException("unrec: " + tagAndFile);
            }
        }
    }

    CryptoDocument (String buildDirectory, String keyDirectory, String resultFile) throws Exception {
        this.buildDirectory = buildDirectory;
        this.template =  readStringFile(DOC_GEN_DIRECTORY + File.separator + "crypto-template.html");
        process(new String[]{"hex/ad.cbor", "txt/AD.txt",
                             "hex/sad.cbor", "txt/SAD.txt",
                             "hex/esad.cbor", "txt/ESAD.txt"});

        ArrayUtil.writeFile(resultFile, template.getBytes("utf-8"));
     }

    public static void main(String[] argc) {
        try {
            new CryptoDocument(argc[0], argc[1], argc[2]);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
