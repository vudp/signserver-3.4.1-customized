package org.signserver.validationservice.server;

import com.itextpdf.text.BaseColor;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Enumeration;
import java.util.List;
import javax.xml.bind.DatatypeConverter;
import vn.mobileid.exsig.*;

public class TestSignHash {

    final protected static String FILE_KEYSTORE = "file/hoann.p12";
    final protected static String KEYSTORE_PASS = "12345678";
    final protected static String FILE_DIRECTORY_PDF = "file/pdf/";

    final public static String[] FILE_PDF
            = new String[]{
                "document.pdf",
                "document.password.encryted.pdf",};
    final public static String[] PDF_PASSWORD
            = new String[]{
                null,
                "12345678"
            };

    static byte[] temp = null;

    final public static String FILE_IMAGE = "Signature.png";
    final public static String FILE_BACKGROUND = "Test.png";

    public static void main(String[] args) throws Exception {
        BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));

        printUsage();
        int resultCode = 0;
        do {
            System.out.print("Enter the function: ");
            resultCode = Integer.parseInt(reader.readLine());
            switch (resultCode) {
                case 1:
                    pdf_prepareHash();
                    break;
                case 2:
                    pdf_authorize();
                    break;
                default:
                    break;
            }
        } while (resultCode != 0);
    }

    private static void printUsage() {
        System.out.println("Welcome to eSignCloud Service");
        System.out.println("There are functions we support");
        System.out.println("1. Prepare hash PDF");
        System.out.println("2. authorize PDF");
    }

    private static void pdf_prepareHash() throws Exception {
        SigningMethod signingMethod = getSigningMethod();
        Calendar calendar = Calendar.getInstance();
        List<byte[]> src = new ArrayList<byte[]>();
        {
            File file = new File("D:\\MOBILE-ID\\E_Drive\\File\\FileToSign\\ok.pdf");
            byte[] data = Files.readAllBytes(file.toPath());
            src.add(data);
        }
        File imageFile = new File(FILE_DIRECTORY_PDF + FILE_IMAGE);
        byte[] image = Files.readAllBytes(imageFile.toPath());
        PdfProfile profile = new PdfProfile(PdfForm.B);

        profile.setReason("Bác sĩ Trần Văn Phúc, Bệnh viện Đa khoa Xanh Pôn, cho biết vi khuẩn Clostridium là một loại trực khuẩn hình que, tồn tại rất rộng rãi trong tự nhiên, có thể tìm thấy trong đất và phân, nước ao, nước sông hồ, thậm chí trong các hạt bụi bẩn hay ở động vật... Vi khuẩn này rất sợ axit và nhiệt, kỵ khí.");
        //profile.setLocation("HO CHI MINH CITY");
        profile.setTextContent("Ký bởi: {signby}\nChức danh: Trưởng phòng nhân sự\nKhối: Hỗ trợ KH cá nhân\nKý ngày: {date}\nMã trình ký:7254\nNội dung: {reason}");
        profile.setPosition("1", "0,0,300,145");

        profile.setVisible(true);
        profile.setCertified(false);

//        profile.setImage(image,ImageProfile.IMAGE_CENTER);
        profile.setFont(DefaultFont.Arial, 9, 1.3f, TextAlignment.ALIGN_LEFT, BaseColor.BLACK);
        profile.setSigningTime(calendar, "dd/MM/yyyy h:mm:ss a");
        profile.setSigningMethod(signingMethod);

        profile.createTemporalFile(src, Arrays.asList(PDF_PASSWORD));
    }

    private static void pdf_authorize() throws Exception {
        BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
        System.out.println("signature (ex: 12312313,12312) :");
        String hash = reader.readLine();
        List<String> hashList = Arrays.asList(hash.split(","));
        List<byte[]> signatureList = new ArrayList<byte[]>();

        for (String hashString : hashList) {
            byte[] signature = null;
            signatureList.add(signature);

        }

        List<byte[]> result = CmsProfile.sign(getAuthorizeMethod(signatureList, temp));
        for (int i = 0; i < result.size(); i++) {
            
            FileOutputStream os = new FileOutputStream("D:\\MOBILE-ID\\E_Drive\\File\\FileToSign\\ok_signed.pdf");
            os.write(result.get(i));
            os.close();
        }
    }

    public static SigningMethod getSigningMethod() {
        return new SigningMethod() {
            Algorithm algorithm = Algorithm.SHA256;
            @Override
            public List<byte[]> sign(List<byte[]> hashList) {
                return null;
            }

            @Override
            public List<byte[]> getCertificate() {
                try {
                    List<byte[]> certs = new ArrayList<byte[]>();
                    KeyStore ks = KeyStore.getInstance("PKCS12");
                    ks.load(new FileInputStream(FILE_KEYSTORE), KEYSTORE_PASS.toCharArray());
                    Enumeration<String> aliases = ks.aliases();
                    aliases.hasMoreElements();
                    String alias = aliases.nextElement();
                    for (Certificate certificate : ks.getCertificateChain(alias)) {
                        certs.add(certificate.getEncoded());
                    }
                    return certs;
                } catch (Exception ex) {
                    return null;
                }
            }

            @Override
            public Algorithm getAlgorithm() {
                return algorithm;
            }

            @Override
            public void generateTempFile(List<byte[]> hashList, byte[] temp) {
                try {
                    String hashString = "";
                    for (byte[] hash : hashList) {
                        hash = DatatypeConverter.parseBase64Binary(new String(hash));
                        StringBuilder sb = new StringBuilder();
                        for (byte b : hash) {
                            sb.append(String.format("%02X", b));
                        }
                        hashString = hashString + sb.toString() + ",";
                    }
                    System.out.println(hashString.substring(0, hashString.length() - 1));
                    TestSignHash.temp = temp;
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        };
    }

    public static AuthorizeMethod getAuthorizeMethod(final List<byte[]> signatureList, final byte[] temp) throws IOException, ClassNotFoundException {

        return new AuthorizeMethod() {
            @Override
            public List<byte[]> authorize() {
                return signatureList;
            }

            @Override
            public byte[] getTempData() {
                return temp;
            }
        };
    }

    public static void showResults(List<VerifyResult> verifyResults) {
        if (verifyResults != null) {
            for (VerifyResult verifyResult : verifyResults) {
                if (verifyResult != null) {
                    System.out.println("    Signature Valid : " + verifyResult.isSignatureValid());
                    System.out.println("    Signature ID : " + verifyResult.getId());
                    System.out.println("    Signing Form : " + verifyResult.getSigningForm());
                    if (verifyResult.getSigningCertificate() != null) {
                        System.out.println("    Signing Certificate : " + verifyResult.getSigningCertificate().getSubjectDN().getName());
                    } else {
                        System.out.println("    Signing Certificate : " + verifyResult.getSigningCertificate());
                    }
                    System.out.println("    Algorithms : " + verifyResult.getAlgorithm());
                    System.out.println("    Signing Time : " + verifyResult.getSigningTimes());
                    if (!verifyResult.isSignatureValid()) {
                        for (int i = 0; i < 10; i++) {
                            System.out.println("##########################################################");
                        }
                    }
                    System.out.println();
                }
            }
        }
    }
}

