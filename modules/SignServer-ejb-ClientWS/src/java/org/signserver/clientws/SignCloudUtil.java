package org.signserver.clientws;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.List;
import org.apache.log4j.Logger;

public class SignCloudUtil {

    private static final Logger LOG = Logger.getLogger(SignCloudUtil.class);

    public static boolean isNullOrEmpty(String value) {
        if (value == null) {
            return true;
        }
        if (value.equals("")) {
            return true;
        }
        return false;
    }

    public static String resolveDNAttribute(String inputString) {
        //final String[] metaCharacters = {"\\", "^", "$", "{", "}", "[", "]", "(", ")", ".", "*", "+", "?", "|", "<", ">", "-", "&", "%", "=", ",", "\""};
        final String[] metaCharacters = {"\\", "+", "=", ",", "\""};
        for (int i = 0; i < metaCharacters.length; i++) {
            if (inputString.contains(metaCharacters[i])) {
                inputString = inputString.replace(metaCharacters[i], "\\" + metaCharacters[i]);
            }
        }
        return inputString;
    }

    public static String getMetaData(SignCloudMetaData signCloudMetaData, String name) {
        List<Metadata> metaDatas = signCloudMetaData.getMetaData();
        for (Metadata metaData : metaDatas) {
            if (metaData.getName().equals(name)) {
                return metaData.getValue();
            }
        }
        return null;
    }

    public static void storeSignedFile(byte[] signedData, String fileName) {
        String DIRECTORY = System.getProperty("user.home") + "/";
        writeBytesToFile(signedData, DIRECTORY + fileName);
    }

    private static void writeBytesToFile(byte[] bFile, String fileDest) {
        LOG.info("Storing file " + fileDest);
        FileOutputStream fileOuputStream = null;
        try {
            fileOuputStream = new FileOutputStream(fileDest);
            fileOuputStream.write(bFile);
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            if (fileOuputStream != null) {
                try {
                    fileOuputStream.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }

    public static byte[] getSignedFile(String fileName) {
        String DIRECTORY = System.getProperty("user.home") + "/";
        return readBytesFromFile(DIRECTORY + fileName);
    }

    private static byte[] readBytesFromFile(String filePath) {
        FileInputStream fileInputStream = null;
        byte[] bytesArray = null;
        try {
            File file = new File(filePath);
            bytesArray = new byte[(int) file.length()];
            //read file into bytes[]
            fileInputStream = new FileInputStream(file);
            fileInputStream.read(bytesArray);
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            if (fileInputStream != null) {
                try {
                    fileInputStream.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }

        }
        return bytesArray;
    }
}