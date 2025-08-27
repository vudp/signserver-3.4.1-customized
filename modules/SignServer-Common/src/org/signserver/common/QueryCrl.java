package org.signserver.common;

import java.util.*;
import java.io.*;
import java.net.*;
import java.security.cert.*;
import java.nio.channels.FileChannel;

import org.apache.log4j.Logger;

import org.apache.commons.io.IOUtils;
import org.signserver.common.util.*;

public class QueryCrl {

    private static final Logger LOG = Logger.getLogger(QueryCrl.class);
    private static final String CRL_PATH = System.getProperty("jboss.server.home.dir") + "/" + "../../../../../file/crl/";

    public static List<CrlFile> getCrlFiles(String crlPath) {
        List<CrlFile> result = null;
        try {
            int index = crlPath.lastIndexOf("/");
            String crlFileName = crlPath.substring(++index);

            File folder = new File(CRL_PATH);

            File[] listOfFiles = folder.listFiles();

            Arrays.sort(listOfFiles, Collections.reverseOrder());

            result = new ArrayList<CrlFile>();

            for (File listOfFile : listOfFiles) {
                if (listOfFile.isFile()) {
                    String crlFile = listOfFile.getName();
                    if (crlFile.contains(crlFileName)) {
                        LOG.debug("Get CRL "+crlFile);
                        CrlFile crlFileResp = new CrlFile();
                        crlFileResp.setFileName(listOfFile.getName());
                        crlFileResp.setLastModify(getUpdateDate(listOfFile));
                        crlFileResp.setNextModify(getExpiredDate(listOfFile));
                        crlFileResp.setSizeOfFile(listOfFile.length());

                        result.add(crlFileResp);
                    }
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return result;
    }

    public static byte[] getCrlFile(String crlPath) {
        byte[] crlData = null;
        try {

            int index = crlPath.lastIndexOf("/");
            String crlFileName = crlPath.substring(++index);

            File fileCrl = new File(CRL_PATH + crlFileName);
            FileInputStream fis = new FileInputStream(CRL_PATH + crlFileName);

            crlData = new byte[(int) fileCrl.length()];
            fis.read(crlData);
            fis.close();

        } catch (Exception e) {
            e.printStackTrace();
        }
        return crlData;
    }

    public static boolean reloadCrlFile(String crlUrl, String crlPath, String caName, boolean isPrimaryCA, boolean isTSA, int endpointConfigId) {
        boolean rv = false;

        try {
            byte[] downloadedFile = EndpointService.getInstance().downloadCrl(crlUrl, endpointConfigId);

            if (downloadedFile == null) {
                LOG.info("Cannot download crl data through endpoint. Try downloading through local service.");
                LocalService localService = new LocalService();
                downloadedFile = localService.downloadCrl(crlUrl, endpointConfigId);
            }

            if (downloadedFile != null) {
                int index = crlPath.lastIndexOf("/");
                String crlFileName = crlPath.substring(++index);
                String src = CRL_PATH + crlFileName;
                LOG.info("CRL successfully downloaded and saved in " + src);
                copyFile(downloadedFile, new File(src));
                rv = true;
                if (!isTSA) {
                    if (isPrimaryCA) {
                        DBConnector.getInstances().CAUpdateDownloadableCRL(
                                caName,
                                true,
                                null);
                    } else {
                        DBConnector.getInstances().CAUpdateDownloadableCRL(
                                caName,
                                null,
                                true);
                    }
                } else {
                    DBConnector.getInstances().updateDownloadableCrlTsa(caName, true);
                }

            } else {
                if (!isTSA) {
                    if (isPrimaryCA) {
                        DBConnector.getInstances().CAUpdateDownloadableCRL(
                                caName,
                                false,
                                null);
                    } else {
                        DBConnector.getInstances().CAUpdateDownloadableCRL(
                                caName,
                                null,
                                false);
                    }
                } else {
                    DBConnector.getInstances().updateDownloadableCrlTsa(caName, false);
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return rv;
    }

    public static byte[] reloadCrlFileAndGetByte(String crlUrl, String crlPath, int endpointConfigId) {
        byte[] downloadedFile = null;
        try {
            downloadedFile = EndpointService.getInstance().downloadCrl(crlUrl, endpointConfigId);

            if (downloadedFile == null) {
                LOG.info("Cannot download crl data through endpoint. Try downloading through local service.");
                LocalService localService = new LocalService();
                downloadedFile = localService.downloadCrl(crlUrl, endpointConfigId);
            }

            if (downloadedFile != null) {
                int index = crlPath.lastIndexOf("/");
                String crlFileName = crlPath.substring(++index);
                String src = CRL_PATH + crlFileName;
                LOG.info("CRL successfully downloaded and saved in " + src);
                copyFile(downloadedFile, new File(src));
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return downloadedFile;
    }

    public static boolean uploadCrlFile(byte[] crlData, String crlPath) {
        boolean rv = false;
        try {
            int index = crlPath.lastIndexOf("/");
            String crlFileName = crlPath.substring(++index);
            String src = CRL_PATH + crlFileName;
            copyFile(crlData, new File(src));
            rv = true;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return rv;
    }

    private static String downloadUrl(final String urlString) {
        String filePath = null;
        try {
            BufferedInputStream in = null;
            FileOutputStream fout = null;
            try {
                filePath = Defines.TMP_DIR + "/"
                        + UUID.randomUUID().toString();

                in = new BufferedInputStream(new URL(urlString).openStream());
                fout = new FileOutputStream(filePath);

                final byte data[] = new byte[1024];
                int count;
                while ((count = in.read(data, 0, 1024)) != -1) {
                    fout.write(data, 0, count);
                }

            } finally {
                if (in != null) {
                    in.close();
                }
                if (fout != null) {
                    fout.close();
                }
            }
        } catch (Exception e) {
            LOG.error("Error while retreiving crl from " + urlString);
            filePath = null;
        }
        return filePath;
    }

    private static void copyFile(File sourceFile, File destFile) {
        try {
            if (!destFile.exists()) {
                destFile.createNewFile();
            }

            FileChannel source = null;
            FileChannel destination = null;

            try {
                source = new FileInputStream(sourceFile).getChannel();
                destination = new FileOutputStream(destFile).getChannel();
                destination.transferFrom(source, 0, source.size());
            } finally {
                if (source != null) {
                    source.close();
                }
                if (destination != null) {
                    destination.close();
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static void copyFile(byte[] sourceFile, File destFile) {
        try {
            String desFilePath = destFile.getAbsolutePath();
            if (!destFile.exists()) {
                destFile.createNewFile();
            }
            OutputStream os = new FileOutputStream(destFile);
            IOUtils.write(sourceFile, os);
            os.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static Date getUpdateDate(File crlPath) {
        Date d = null;
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509CRL crl = (X509CRL) cf.generateCRL(new FileInputStream(crlPath));
            d = crl.getThisUpdate();
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return d;
    }

    private static Date getExpiredDate(File crlPath) {
        Date d = null;
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509CRL crl = (X509CRL) cf.generateCRL(new FileInputStream(crlPath));
            d = crl.getNextUpdate();
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return d;
    }
}