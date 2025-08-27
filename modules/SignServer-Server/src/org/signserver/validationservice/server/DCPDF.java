package org.signserver.validationservice.server;

import SecureBlackbox.PDF.TElPDFCIDFont;
import SecureBlackbox.PDF.TElPDFCIDFontDescriptor;
import SecureBlackbox.PDF.TElPDFCIDSystemInfo;
import SecureBlackbox.PDF.TElPDFCompositeFont;
import SecureBlackbox.PDF.TElPDFSignatureWidgetProps;
import com.itextpdf.text.BaseColor;

import org.apache.commons.io.IOUtils;

import java.io.*;
import java.awt.image.*;

import javax.imageio.ImageIO;

import org.signserver.common.util.*;

import java.security.cert.Certificate;


import javax.xml.bind.DatatypeConverter;

import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.List;
import net.coobird.thumbnailator.Thumbnails;
import org.apache.commons.lang.StringEscapeUtils;
import org.apache.log4j.Logger;
import org.signserver.common.DBConnector;
import org.signserver.common.dbdao.Ca;
import vn.mobileid.exsig.*;

public class DCPDF implements DC {

    private static final Logger LOG = Logger.getLogger(DCPDF.class);
    private static final String EXTERNTTF = System.getProperty("jboss.server.home.dir") + "/../../../../../../CAG360/file/FontUnicode.ttf";
    private static final String EXTERNUFM = System.getProperty("jboss.server.home.dir") + "/../../../../../../CAG360/file/FontUnicode.ufm";
    private static final String EXTERNTTF_ARIAL = System.getProperty("jboss.server.home.dir") + "/../../../../../../CAG360/file/arial.ttf";
    private static final String EXTERNUFM_ARIAL = System.getProperty("jboss.server.home.dir") + "/../../../../../../CAG360/file/arial.ufm";
    private static final int DEFAULT_RECTANGLE_OFFSETX = 0;
    private static final int DEFAULT_RECTANGLE_OFFSETY = 0;
    private static final int DEFAULT_RECTANGLE_WIDTH = 400;
    private static final int DEFAULT_RECTANGLE_HEIGHT = 100;
    private static final String DEFUALT_SIGNERINFO_PREFIX = "Ký bởi:";
    private static final String DEFUALT_DATETIME_PREFIX = "Ký ngày:";
    private static final String DEFUALT_SIGNREASON_PREFIX = "Nội dung:";
    private static final String DEFUALT_TITLE_PREFIX = "Chức danh:";
    private static final String DEFUALT_ORGANIZATION_PREFIX = "Đơn vị:";
    private static final String DEFUALT_ORGANIZATIONUNIT_PREFIX = "Phòng ban:";
    private static final String DEFUALT_SIGNINGID_PREFIX = "Mã trình ký:";
    private static final int DEFAULT_PAGE_NO = 1;
    private static final boolean DEFAULT_VISUAL_STATUS = false;
    private static final int FONT_SIZE = 9;
    private static final int RATIO_LINE_BREAK = 5; // font size 10
    final public static String[] PDF_PASSWORD = new String[]{
        null,
        null,};

    public DCPDF() {
        /*
         * CryptoS.getInstance(IValidator.class, 1); SBPDF.initialize();
         * SBPAdES.initialize(); SBPDFSecurity.initialize();
         *
         * SBHTTPCRL.registerHTTPCRLRetrieverFactory();
         * SBLDAPCRL.registerLDAPCRLRetrieverFactory();
         * SBHTTPOCSPClient.registerHTTPOCSPClientFactory();
         * SBHTTPCertRetriever.registerHTTPCertificateRetrieverFactory();
         * SBLDAPCertRetriever.registerLDAPCertificateRetrieverFactory();
         */
    }

    public DCPDFResponse signInit(
            byte[] fileData,
            Properties signaturePro) {
        DCPDFResponse response = new DCPDFResponse();
        try {
            // signature properties
            String visibleSignature = signaturePro.getProperty(Defines._VISIBLESIGNATURE);
            String coordinate = signaturePro.getProperty(Defines._COORDINATE);
            String pageNo = signaturePro.getProperty(Defines._PAGENO);
            String signReason = signaturePro.getProperty(Defines._SIGNREASON);
            signReason = StringEscapeUtils.unescapeXml(signReason);

            String visualStatus = signaturePro.getProperty(Defines._VISUALSTATUS);
            String signatureImage = signaturePro.getProperty(Defines._SIGNATUREIMAGE);
            String certificate = signaturePro.getProperty(Defines._CERTIFICATE);
            String signerInfoPrefix = signaturePro.getProperty(Defines._SIGNERINFOPREFIX);
            String dateTimePrefix = signaturePro.getProperty(Defines._DATETIMEPREFIX);
            String signReasonPrefix = signaturePro.getProperty(Defines._SIGNREASONPREFIX);
            String location = signaturePro.getProperty(Defines._LOCATION);
            location = StringEscapeUtils.unescapeXml(location);

            String showTitle = signaturePro.getProperty(Defines._SHOWTITLE);
            String titlePrefix = signaturePro.getProperty(Defines._TITLEPREFIX);
            String title = signaturePro.getProperty(Defines._TITLE);
            title = StringEscapeUtils.unescapeXml(title);

            String showOrganization = signaturePro.getProperty(Defines._SHOWORGANIZATION);
            String organizationPrefix = signaturePro.getProperty(Defines._ORGANIZATIONPREFIX);
            String organization = signaturePro.getProperty(Defines._ORGANIZATION);

            String showOrganizationUnit = signaturePro.getProperty(Defines._SHOWORGANIZATIONUNIT);
            String organizationUnitPrefix = signaturePro.getProperty(Defines._ORGANIZATIONUNITPREFIX);
            String organizationUnit = signaturePro.getProperty(Defines._ORGANIZATIONUNIT);

            String showSigningID = signaturePro.getProperty(Defines._SHOWSIGNINGID);
            String signingIDPrefix = signaturePro.getProperty(Defines._SIGNINGIDPREFIX);
            String signingID = signaturePro.getProperty(Defines._SIGNINGID);
            String datetimeFormat = signaturePro.getProperty(Defines._DATETIMEFORMAT);
            String fontName = signaturePro.getProperty(Defines._FONTNAME);

            boolean isShowSignature = false;
            boolean isShowVisualStatus = false;

            String[] certs = ExtFunc.getCertificateComponents(certificate);

            boolean isShowTitle = false;
            boolean isShowOrganization = false;
            boolean isShowOrganizationUnit = false;
            boolean isShowSigingID = false;

            if (showTitle != null) {
                if (showTitle.compareToIgnoreCase(Defines.TRUE) == 0) {
                    isShowTitle = true;
                    if (!ExtFunc.isNullOrEmpty(title)) {
                        if (!ExtFunc.isNullOrEmpty(titlePrefix)) {
                            title = titlePrefix + " " + title;
                        }
                    } else {
                        title = ExtFunc.getTitle(certs[1]);
                        if (!ExtFunc.isNullOrEmpty(title)) {
                            if (!ExtFunc.isNullOrEmpty(titlePrefix)) {
                                title = titlePrefix + " " + title;
                            }
                        } else {
                            isShowTitle = false;
                        }
                    }
                }
            }

            if (showOrganization != null) {
                if (showOrganization.compareToIgnoreCase(Defines.TRUE) == 0) {
                    isShowOrganization = true;
                    if (!ExtFunc.isNullOrEmpty(organization)) {
                        if (!ExtFunc.isNullOrEmpty(organizationPrefix)) {
                            organization = organizationPrefix + " " + organization;
                        }
                    } else {
                        organization = ExtFunc.getOrganization(certs[1]);
                        if (!ExtFunc.isNullOrEmpty(organization)) {
                            if (!ExtFunc.isNullOrEmpty(organizationPrefix)) {
                                organization = organizationPrefix + " " + organization;
                            }
                        } else {
                            isShowOrganization = false;
                        }
                    }
                }
            }

            if (showOrganizationUnit != null) {
                if (showOrganizationUnit.compareToIgnoreCase(Defines.TRUE) == 0) {
                    isShowOrganizationUnit = true;
                    if (!ExtFunc.isNullOrEmpty(organizationUnit)) {
                        if (!ExtFunc.isNullOrEmpty(organizationUnitPrefix)) {
                            organizationUnit = organizationUnitPrefix + " " + organizationUnit;
                        }
                    } else {
                        organizationUnit = ExtFunc.getOrganizationUnit(certs[1]);
                        if (!ExtFunc.isNullOrEmpty(organizationUnit)) {
                            if (!ExtFunc.isNullOrEmpty(organizationUnitPrefix)) {
                                organizationUnit = organizationUnitPrefix + " " + organizationUnit;
                            }
                        } else {
                            isShowOrganizationUnit = false;
                        }
                    }
                }
            }

            if (showSigningID != null) {
                if (showSigningID.compareToIgnoreCase(Defines.TRUE) == 0) {
                    isShowSigingID = true;
                    if (!ExtFunc.isNullOrEmpty(signingID)) {
                        if (!ExtFunc.isNullOrEmpty(signingIDPrefix)) {
                            signingID = signingIDPrefix + " " + signingID;
                        }
                    } else {
                        isShowSigingID = false;
                    }
                }
            }

            if (visibleSignature.compareToIgnoreCase(Defines.TRUE) == 0) {
                isShowSignature = true;
                if (visualStatus.compareToIgnoreCase(Defines.TRUE) == 0) {
                    isShowVisualStatus = true;
                }
            }

            ArrayList<Ca> cas = DBConnector.getInstances().getCAProviders();

            X509Certificate sigingCert = ExtFunc.getX509Object(certificate);

            String authorityKeyIdentifier = ExtFunc.getIssuerKeyIdentifier(sigingCert);

            boolean CAFound = false;
            Ca caIssuer = null;

            for (Ca ca : cas) {
                if (ca.getSubjectKeyIdentifier1().compareToIgnoreCase(authorityKeyIdentifier) == 0
                        || ca.getSubjectKeyIdentifier2().compareToIgnoreCase(authorityKeyIdentifier) == 0) {
                    caIssuer = ca;
                    CAFound = true;
                    break;
                }
            }

            if (!CAFound) {
                LOG.error("CA " + sigingCert.getIssuerDN().toString() + " not found.");
                response.setResponseCode(Defines.CODE_INVALIDISSUERCERT);
                response.setResponseMessage(Defines.ERROR_INVALIDISSUERCERT);
                return response;
            }
            //tcb issue
            //List<Certificate> certificates = ExtFunc.getCertificateChain(caIssuer.getCert(), caIssuer.getCert2(), sigingCert);

            List<Certificate> certificates = new ArrayList<Certificate>();
            certificates.add(sigingCert);

            // Hoa's lib
            MySigningMethod signingMethod = getSigningMethod(certificates);
            Calendar calendar = Calendar.getInstance();
            List<byte[]> src = new ArrayList<byte[]>();
            {
                src.add(fileData);
            }
            byte[] image = null;
            if (signatureImage != null) {
                if (!signatureImage.equals("")) {
                    image = DatatypeConverter.parseBase64Binary(signatureImage);
                }
            }

            PdfProfile profile = new PdfProfile(PdfForm.B);

            if (signReason != null) {
                profile.setReason(signReason);
            }
            if (location != null) {
                profile.setLocation(location);
            }

            String textContent = "";

            if (ExtFunc.isNullOrEmpty(signerInfoPrefix)) {
                signerInfoPrefix = DEFUALT_SIGNERINFO_PREFIX;
            }

            textContent += signerInfoPrefix + " {signby}\n";

            if (isShowTitle) {
                textContent += title + "\n";
            }

            if (isShowOrganizationUnit) {
                textContent += organizationUnit + "\n";
            }

            if (isShowOrganization) {
                textContent += organization + "\n";
            }

            if (ExtFunc.isNullOrEmpty(dateTimePrefix)) {
                dateTimePrefix = DEFUALT_DATETIME_PREFIX;
            }

            textContent += dateTimePrefix + " {date}\n";

            if (isShowSigingID) {
                textContent += signingID + "\n";
            }

            if (signReason != null) {
                textContent += signReasonPrefix + " {reason}\n";
            }

//            if(location != null) {
//                textContent +=  + ": {location}\n";
//            }

            profile.setTextContent(textContent);

            // check mark calculation
            int checkmarkOffsetX = 30;
            int checkmarkOffsetY = 30;

            int upperY = 0;

            if (coordinate != null) {
                profile.setPosition(pageNo, coordinate);
                String[] parts = coordinate.split(",");
                checkmarkOffsetX = (Integer.parseInt(parts[2]) - Integer.parseInt(parts[0])) / 2;
                checkmarkOffsetY = (Integer.parseInt(parts[3]) - Integer.parseInt(parts[1])) / 2;
                upperY = Integer.parseInt(parts[3]) - Integer.parseInt(parts[1]);
            } else {
                profile.setPosition(pageNo, "0,0,279,145");
                checkmarkOffsetX = 279 / 2;
                checkmarkOffsetY = 145 / 2;
                upperY = 145;
            }
            if (image != null) {
                profile.setBackground(image);
            }
            profile.setVisible(isShowSignature);
            profile.setCertified(false);
            profile.setCheckMark(true, "30, " + checkmarkOffsetX + ", " + checkmarkOffsetY);
            profile.setCheckText(true, "10, " + (upperY - 20) + ", 90, " + upperY);

            if (fontName != null) {
                if (fontName.compareToIgnoreCase("arial") == 0) {
                    profile.setFont(DefaultFont.Arial, 9, 1.3f, TextAlignment.ALIGN_LEFT, BaseColor.BLACK);
                } else if (fontName.compareToIgnoreCase("verdana") == 0) {
                    profile.setFont(DefaultFont.Verdana, 9, 1.3f, TextAlignment.ALIGN_LEFT, BaseColor.BLACK);
                } else if (fontName.compareToIgnoreCase("tahoma") == 0) {
                    profile.setFont(DefaultFont.Tahoma, 9, 1.3f, TextAlignment.ALIGN_LEFT, BaseColor.BLACK);
                } else {
                    profile.setFont(DefaultFont.Times, 9, 1.3f, TextAlignment.ALIGN_LEFT, BaseColor.BLACK);
                }
            } else {
                profile.setFont(DefaultFont.Times, 9, 1.3f, TextAlignment.ALIGN_LEFT, BaseColor.BLACK);
            }

            if (datetimeFormat != null) {
                profile.setSigningTime(calendar, datetimeFormat);
            } else {
                profile.setSigningTime(calendar);
            }

            profile.setSigningMethod(signingMethod);
            profile.createTemporalFile(src, Arrays.asList(PDF_PASSWORD));

            String hash = signingMethod.getHash();
            byte[] temp = signingMethod.getTemp();

            String streamDataPath = Defines.TMP_DIR + "/" + UUID.randomUUID().toString();
            FileOutputStream oStreamDataPath = new FileOutputStream(new File(streamDataPath));
            IOUtils.write(temp, oStreamDataPath);
            oStreamDataPath.close();

            // SecureblackBox
//            boolean createAdES = false;
//            byte[] docBin = fileData;
//            TElMemoryStream doc = new TElMemoryStream(docBin, 0, docBin.length);
//            TElMemoryStream output = new TElMemoryStream();
//
//            TElDCAsyncState state;
//
//            TElPDFDocument pdf = new TElPDFDocument();
//            TElPDFSecurityHandler handler;
//
//            pdf.open(doc);
//
//            if (createAdES) {
//                handler = new TElPDFAdvancedPublicKeySecurityHandler();
//
//                ((TElPDFAdvancedPublicKeySecurityHandler) handler).setPAdESSignatureType(TSBPAdESSignatureType.pastEnhanced);
//                ((TElPDFAdvancedPublicKeySecurityHandler) handler).setHashAlgorithm(SBConstants.SB_ALGORITHM_DGST_SHA1); // SB_ALGORITHM_DGST_SHA1
//                ((TElPDFAdvancedPublicKeySecurityHandler) handler).setCustomName("Adobe.PPKMS");
//            } else {
//                handler = new TElPDFPublicKeySecurityHandler();
//
//                ((TElPDFPublicKeySecurityHandler) handler).setSignatureType(TSBPDFPublicKeySignatureType.pstPKCS7SHA1);
//                ((TElPDFPublicKeySecurityHandler) handler).setHashAlgorithm(SBConstants.SB_ALGORITHM_DGST_SHA1); // SB_ALGORITHM_DGST_SHA1
//                ((TElPDFPublicKeySecurityHandler) handler).setCustomName("Adobe.PPKMS");
//            }
//
//            TElPDFSignature signature = pdf.getSignatureEntry(pdf.addSignature());
//
//
//            TElPDFSignatureWidgetProps widgetPro = signature.getWidgetProps();
//
//            widgetPro.setAutoSize(false);
//            widgetPro.setAutoPos(false);
//            widgetPro.setAutoFontSize(false);
//            widgetPro.setOffsetX(sigPro_rec_OffsetX);
//            widgetPro.setOffsetY(sigPro_rec_OffsetY);
//            widgetPro.setWidth(sigPro_rec_Width);
//            widgetPro.setHeight(sigPro_rec_Heigth);
//            widgetPro.setSectionTextFontSize(FONT_SIZE);
//            widgetPro.setSectionTitleFontSize(FONT_SIZE);
//            widgetPro.clearImages();
//            widgetPro.setBackgroundStyle(TSBPDFWidgetBackgroundStyle.pbsNoBackground);
//            widgetPro.setHideDefaultText(true);
//
//            if (isUseImage) {
//                BufferedImage bufImg = ImageIO.read(new ByteArrayInputStream(DatatypeConverter.parseBase64Binary(signatureImage)));
//
//                if (bufImg == null) {
//                    response.setResponseCode(Defines.CODE_INVALIDPARAMETER);
//                    response.setResponseMessage(Defines.ERROR_INVALIDPARAMETER);
//                    response.setData(null);
//                    return response;
//                }
//                // extra add 2018-05-18
//                BufferedImage resizedBufImg = resize(bufImg, sigPro_rec_Width, sigPro_rec_Heigth);
//
//                TElPDFImage pdfImage = new TElPDFImage();
//                pdfImage.setImageType(TSBPDFImageType.pitJPEG);
//
//                pdfImage.setWidth(resizedBufImg.getWidth());
//                pdfImage.setHeight(resizedBufImg.getHeight());
//                pdfImage.setData(getBytesFromBufferedImage(resizedBufImg));
//
//
//                widgetPro.addImage(
//                        pdfImage,
//                        sigPro_rec_OffsetX,
//                        sigPro_rec_OffsetY,
//                        pdfImage.getWidth(),
//                        pdfImage.getHeight());
//            }
//            String ttf = EXTERNTTF;
//            String ufm = EXTERNUFM;
//
//            if (ExtFunc.isNullOrEmpty(fontName)) {
//                AddTrueTypeFont(widgetPro, ttf, ufm);
//            } else {
//                if (fontName.compareToIgnoreCase("arial") == 0) {
//                    AddTrueTypeFont(widgetPro, EXTERNTTF_ARIAL, EXTERNUFM_ARIAL);
//                } else {
//                    AddTrueTypeFont(widgetPro, ttf, ufm);
//                }
//            }
//
//            //DateFormat formatter = new SimpleDateFormat("dd-MM-yyyy HH:mm:ss");
//            Calendar cal = Calendar.getInstance();
//
//            String strDateTime = getDateTimeAsString(cal.getTime(), datetimeFormat);
//
//            String signDate = dateTimePrefix != null ? dateTimePrefix + " " + strDateTime : DEFUALT_DATETIME_PREFIX + " " + strDateTime;
//
//            String cn = ExtFunc.getCommonName(certs[1]);
//            String signBy = signerInfoPrefix != null ? signerInfoPrefix + " " + cn : DEFUALT_SIGNERINFO_PREFIX + " " + cn;
//
//            int lineSpacing = 10;
//            widgetPro.getCustomText().add("", 5, sigPro_rec_Heigth - lineSpacing, FONT_SIZE / 2);
//            lineSpacing = lineSpacing + 10;
//
//            widgetPro.getCustomText().add(signBy, 5, sigPro_rec_Heigth - lineSpacing, FONT_SIZE);
//            lineSpacing = lineSpacing + 10;
//            if (isShowTitle) {
//                widgetPro.getCustomText().add(title, 5, sigPro_rec_Heigth - lineSpacing, FONT_SIZE);
//                lineSpacing = lineSpacing + 10;
//            }
//            if (isShowOrganization) {
//                widgetPro.getCustomText().add(organization, 5, sigPro_rec_Heigth - lineSpacing, FONT_SIZE);
//                lineSpacing = lineSpacing + 10;
//            }
//            if (isShowOrganizationUnit) {
//                widgetPro.getCustomText().add(organizationUnit, 5, sigPro_rec_Heigth - lineSpacing, FONT_SIZE);
//                lineSpacing = lineSpacing + 10;
//            }
//            widgetPro.getCustomText().add(signDate, 5, sigPro_rec_Heigth - lineSpacing, FONT_SIZE);
//            lineSpacing = lineSpacing + 10;
//            if (isShowSigingID) {
//                widgetPro.getCustomText().add(signingID, 5, sigPro_rec_Heigth - lineSpacing, FONT_SIZE);
//                lineSpacing = lineSpacing + 10;
//            }
//            String prefixReason = signReasonPrefix != null ? signReasonPrefix : DEFUALT_SIGNREASON_PREFIX;
//            String reason = prefixReason + " " + signReason;
//            int numOfCharToBreak = sigPro_rec_Width / RATIO_LINE_BREAK;
//
//            if (signReason != null) {
//                String[] lines = lineBreak(reason, numOfCharToBreak);
//                int len = lines.length;
//                if (len == 1) {
//                    widgetPro.getCustomText().add(reason, 5, sigPro_rec_Heigth - lineSpacing, FONT_SIZE);
//                    lineSpacing = lineSpacing + 10;
//                } else {
//                    int tmp = 0;
//                    for (int i = 0; i < len; i++) {
//                        widgetPro.getCustomText().add(lines[i], 5, sigPro_rec_Heigth - (i * 10 + lineSpacing), FONT_SIZE);
//                        tmp = i * 10 + lineSpacing;
//                    }
//                    lineSpacing = lineSpacing + 10;
//                }
//            }
//            widgetPro.getCustomText().add("", 5, sigPro_rec_Heigth - lineSpacing, FONT_SIZE / 2);
//
//            widgetPro.setShowVisualStatus(isShowVisualStatus);
//
//            signature.setAuthorName(cn);
//
//            if (signReason != null) {
//                signature.setReason(signReason);
//            }
//
//            if (pageNo != null) {
//                try {
//                    int pNo = Integer.parseInt(pageNo) - 1;
//                    if (pNo < 0) {
//                        pNo = 0;
//                    }
//                    sigPro_PageNo = pNo;
//                } catch (NumberFormatException e) {
//                    if (pageNo.equals("First")) {
//                        sigPro_PageNo = 0;
//                    } else if (pageNo.equals("Last")) {
//                        sigPro_PageNo = pdf.getPageInfoCount() - 1;
//                    } else {
//                        sigPro_PageNo = 0;
//                    }
//                }
//            }
//
//            signature.setInvisible(!isShowSignature);
//            signature.setPage(sigPro_PageNo);
//            signature.setSignatureType(SBPDF.stDocument);
//            signature.setHandler(handler);
//            signature.setLocation((location == null) ? "" : location);
//            signature.setSigningTime(SBUtils.utcNow());
//
//            state = pdf.initiateAsyncOperation();
//            state.saveToStream(output, SBDCXMLEnc.dcxmlEncoding());
//
//
//            final ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(output.getBuffer());
//            final ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
//            final ElDCStandardServer elDCStandardServer = new ElDCStandardServer();
//
//            final CustomOperationHandler elDCX509SignOperationHandler = new CustomOperationHandler();
//            elDCStandardServer.addOperationHandler((ElDCOperationHandler) elDCX509SignOperationHandler);
//            elDCStandardServer.process((InputStream) byteArrayInputStream, (OutputStream) byteArrayOutputStream);
//
//            byte[] sig = byteArrayOutputStream.toByteArray();
//            byte[] d = elDCX509SignOperationHandler.getDataToSign();
//
//            String streamDataPath = Defines.TMP_DIR + "/" + UUID.randomUUID().toString();
//            FileOutputStream oStreamDataPath = new FileOutputStream(new File(streamDataPath));
//            IOUtils.write(doc.getBuffer(), oStreamDataPath);
//            oStreamDataPath.close();
//
//            String streamSignPath = Defines.TMP_DIR + "/" + UUID.randomUUID().toString();
//            FileOutputStream oStreamSignPath = new FileOutputStream(new File(streamSignPath));
//            IOUtils.write(output.getBuffer(), oStreamSignPath);
//            oStreamSignPath.close();
            response.setResponseCode(Defines.CODE_SUCCESS);
            response.setResponseMessage(Defines.SUCCESS);
            response.setData(DatatypeConverter.parseHexBinary(hash));
            response.setAsynStreamDataPath(streamDataPath);
            response.setAsynStreamSignPath(streamDataPath);

        } catch (Exception e) {
            e.printStackTrace();
            response.setResponseCode(Defines.CODE_INTERNALSYSTEM);
            response.setResponseMessage(Defines.ERROR_INTERNALSYSTEM);
            response.setData(null);
        }
        return response;
    }

    public DCPDFResponse signFinal(String dcStreamDataPath, String dcStreamSignPath, byte[] signature, String base64Cert) {
        DCPDFResponse response = new DCPDFResponse();
        try {

//            byte[] stream = IOUtils.toByteArray(new FileInputStream(dcStreamSignPath));
//            final ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(stream);
//            final ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
//            final ElDCStandardServer elDCStandardServer = new ElDCStandardServer();
//
//            final CustomOperationHandler elDCX509SignOperationHandler = new CustomOperationHandler();
//
//            X509Certificate x509 = ExtFunc.convertToX509Cert(base64Cert);
//
//            elDCX509SignOperationHandler.setSigningCertificate(x509);
//            elDCX509SignOperationHandler.setSignature(signature);
//            elDCStandardServer.addOperationHandler((ElDCOperationHandler) elDCX509SignOperationHandler);
//            elDCStandardServer.process((InputStream) byteArrayInputStream,
//                    (OutputStream) byteArrayOutputStream);
//
//            byte[] sig = byteArrayOutputStream.toByteArray();
//
//
//            TElDCAsyncState state2 = new TElDCAsyncState();
//            TElMemoryStream input = new TElMemoryStream(sig, 0, sig.length);
//            state2.loadFromStream(input, SBDCXMLEnc.dcxmlEncoding());
//
//            TElPDFDocument pdf = new TElPDFDocument();
//            TElPDFPublicKeySecurityHandler handler2 = new TElPDFPublicKeySecurityHandler();
//            handler2.setSignatureType(TSBPDFPublicKeySignatureType.pstPKCS7SHA1);
//
//            byte[] savedDoc = IOUtils.toByteArray(new FileInputStream(dcStreamDataPath));
//
//            TElMemoryStream result = new TElMemoryStream(savedDoc, 0,
//                    savedDoc.length);
//            pdf.completeAsyncOperation(result, state2, handler2);
//            result.setPosition(0);
//            
//            byte[] signedFile = result.getBuffer();

            byte[] signedFile = null;

            List<byte[]> signatureList = new ArrayList<byte[]>();
            signatureList.add(signature);

            byte[] temp = IOUtils.toByteArray(new FileInputStream(dcStreamSignPath));
            List<byte[]> result = PdfProfile.sign(new MyAuthorizeMethod(signatureList, temp));
            for (int i = 0; i < result.size(); i++) {
                signedFile = result.get(0);
            }


            response.setResponseCode(Defines.CODE_SUCCESS);
            response.setResponseMessage(Defines.SUCCESS);
            response.setData(signedFile);
        } catch (Exception e) {
            e.printStackTrace();
            response.setResponseCode(Defines.CODE_INTERNALSYSTEM);
            response.setResponseMessage(Defines.ERROR_INTERNALSYSTEM);
            response.setData(null);
        }
        return response;
    }

    public void AddTrueTypeFont(TElPDFSignatureWidgetProps widgetPro, String ttf, String ufm) throws IOException {
        TElPDFCompositeFont Font0 = new TElPDFCompositeFont();
        TElPDFCIDFont CIDFont = new TElPDFCIDFont();
        TElPDFCIDSystemInfo SystemInfo = new TElPDFCIDSystemInfo();
        TElPDFCIDFontDescriptor FontDescriptor = new TElPDFCIDFontDescriptor();

        byte[] Buf = IOUtils.toByteArray(new FileInputStream(ttf));
        FontDescriptor.setFontFile2(Buf);

        if (new File(ufm).exists()) {
            byte[] CIDToGIDMap = new byte[256 * 256 * 2];
            FontDescriptor.setFlags(32);
            FileInputStream fis = new FileInputStream(ufm);
            BufferedReader br = new BufferedReader(new InputStreamReader(fis));
            while (true) //!sr.EndOfStream
            {
                String s = br.readLine();
                if (s == null) {
                    break;
                }
                s = s.trim();
                if (s == "") {
                    continue;
                }

                String[] t = s.split(" ");
                if (t.length < 2) {
                    continue;
                }

                if (t[0].compareTo("U") == 0) {
                    if (t.length < 11) {
                        continue;
                    }

                    int CID = Integer.parseInt(t[1]);
                    int Width = Integer.parseInt(t[4]);
                    if (CID >= 0) {
                        int GID = Integer.parseInt(t[10]);
                        if ((CID >= 0) && (CID < 0xFFFF) && (GID > 0)) {
                            CIDToGIDMap[CID * 2] = (byte) (GID >> 8);
                            CIDToGIDMap[CID * 2 + 1] = (byte) (GID & 0xFF);
                            CIDFont.getW().add(CID, Width);
                        }

                        if ((t.length > 13) && (CID == (int) 'X')) {
                            FontDescriptor.setXHeight(Integer.parseInt(t[13]));
                        }
                    }
                    if ((t[7].compareTo(".notdef") == 0) && (FontDescriptor.getMissingWidth() == 0)) {
                        FontDescriptor.setMissingWidth(Width);
                    }
                } else if (t[0].compareTo("FontName") == 0) {
                    FontDescriptor.setFontName(t[1]);
                } else if (t[0].compareTo("Weight") == 0) {
                    if (FontDescriptor.getStemV() == 0) {
                        s = t[1].toLowerCase();
                        if ((s.compareTo("bold") == 0) || (s.compareTo("black") == 0)) {
                            FontDescriptor.setStemV(120);
                        } else {
                            FontDescriptor.setStemV(70);
                        }
                    }
                } else if (t[0].compareTo("ItalicAngle") == 0) {
                    FontDescriptor.setItalicAngle(Double.parseDouble(t[1]));

                    if (FontDescriptor.getItalicAngle() != 0) {
                        FontDescriptor.setFlags(FontDescriptor.getFlags() | 64);
                    }
                } else if (t[0].compareTo("Ascender") == 0) {
                    FontDescriptor.setAscent(Integer.parseInt(t[1]));
                } else if (t[0].compareTo("Descender") == 0) {
                    FontDescriptor.setDescent(Integer.parseInt(t[1]));
                } // else if (t[0] == "UnderlineThickness")
                // else if (t[0] == "UnderlinePosition")
                else if (t[0].compareTo("IsFixedPitch") == 0) {
                    if (t[1].compareTo("true") == 0) {
                        FontDescriptor.setFlags(FontDescriptor.getFlags() | 1);
                    }
                } else if (t[0].compareTo("FontBBox") == 0) {
                    if (t.length < 5) {
                        continue;
                    }
                    FontDescriptor.setFontBBoxX1(Integer.parseInt(t[1]));
                    FontDescriptor.setFontBBoxY1(Integer.parseInt(t[2]));
                    FontDescriptor.setFontBBoxX2(Integer.parseInt(t[3]));
                    FontDescriptor.setFontBBoxY2(Integer.parseInt(t[4]));
                } else if (t[0].compareTo("CapHeight") == 0) {
                    FontDescriptor.setCapHeight(Integer.parseInt(t[1]));
                } else if (t[0].compareTo("StdVW") == 0) {
                    FontDescriptor.setStemV(Integer.parseInt(t[1]));
                }
            }
            br.close();

            if (FontDescriptor.getMissingWidth() == 0) {
                FontDescriptor.setMissingWidth(600);
            }
            CIDFont.setCIDToGIDMapData(CIDToGIDMap);
        }

        Font0.setBaseFont(FontDescriptor.getFontName());
        Font0.setEncoding("Identity-H");
        Font0.setResourceName("T1_0"); // the name of font resource used by default signature widget
        Font0.setDescendantFonts(CIDFont);
        SystemInfo.setRegistry("Adobe");
        SystemInfo.setOrdering("UCS");
        CIDFont.setSubtype("CIDFontType2");
        CIDFont.setBaseFont(FontDescriptor.getFontName());
        CIDFont.setCIDSystemInfo(SystemInfo);
        CIDFont.setFontDescriptor(FontDescriptor);

        widgetPro.addFont(Font0);
        widgetPro.addFont(CIDFont);
        widgetPro.addFontObject(SystemInfo);
        widgetPro.addFontObject(FontDescriptor);
    }

    private String[] countLines(String str) {
        String[] lines = str.split("\r\n|\r|\n");
        return lines;
    }

    public byte[] getBytesFromBufferedImage(BufferedImage originalImage)
            throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ImageIO.write(originalImage, "jpg", baos);
        baos.flush();
        byte[] imageInByte = baos.toByteArray();
        baos.close();
        return imageInByte;
    }

    private BufferedImage resize(BufferedImage img, int newW, int newH)
            throws IOException {
        return Thumbnails.of(img).size(newW, newH).asBufferedImage();
    }

    private String getDateTimeAsString(Date dateTime, String format) {
        String strDateTime = null;
        if (format == null) {
            format = "dd-MM-yyyy HH:mm:ss";
        }
        try {
            SimpleDateFormat sdf = new SimpleDateFormat(format);
            strDateTime = sdf.format(dateTime);
        } catch (Exception e) {
            try {
                SimpleDateFormat sdf = new SimpleDateFormat("dd-MM-yyyy HH:mm:ss");
                strDateTime = sdf.format(dateTime);
            } catch (Exception ex) {
            }
        }
        return strDateTime;
    }

    private String[] lineBreak(String content, int numCharsToBreak) {
        String[] words = content.split(" ");
        List<String> listOfWord = new LinkedList<String>(Arrays.asList(words));
        List<String> result = new ArrayList<String>();
        String aLine = "";
        for (int i = 0; i < listOfWord.size(); i++) {
            String item = listOfWord.get(i);
            String strTemp = aLine + item;
            if (strTemp.length() <= numCharsToBreak) {
                aLine += item;
                aLine += " ";
            } else {
                result.add(aLine);
                aLine = "";
                --i;
            }
        }
        if (aLine.compareTo("") != 0) {
            result.add(aLine);
        }
        return result.toArray(new String[0]);
    }

    public static MySigningMethod getSigningMethod(final List<Certificate> certificates) {
        return new MySigningMethod(certificates);
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

    static class MySigningMethod implements SigningMethod {

        Algorithm algorithm = Algorithm.SHA1;
        byte[] temp;
        String hash;
        List<Certificate> certificates;

        public MySigningMethod(List<Certificate> certificates) {
            this.certificates = certificates;
        }

        public byte[] getTemp() {
            return temp;
        }

        public String getHash() {
            return hash;
        }

        @Override
        public List<byte[]> sign(List<byte[]> hashList) {
            return null;
        }

        @Override
        public List<byte[]> getCertificate() {
            try {
                List<byte[]> certs = new ArrayList<byte[]>();
                for (Certificate certificate : certificates) {
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
                    hashString = hashString + sb.toString();
                }
                this.hash = hashString;
                this.temp = temp;
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    static class MyAuthorizeMethod implements AuthorizeMethod {

        List<byte[]> signatureList;
        byte[] temp;

        public MyAuthorizeMethod(List<byte[]> signatureList, byte[] temp) {
            this.signatureList = signatureList;
            this.temp = temp;
        }

        @Override
        public List<byte[]> authorize() {
            return signatureList;
        }

        @Override
        public byte[] getTempData() {
            return temp;
        }
    }
}