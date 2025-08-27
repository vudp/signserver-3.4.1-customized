package org.signserver.common.util;

import java.util.Arrays;

public class MineType
{
    private static byte[] BMP = { (byte) 0x42,(byte) 0x4D};
    private static byte[] DOC = { (byte) 0xD0,(byte) 0xCF,(byte) 0x11,(byte) 0xE0,(byte) 0xA1,(byte) 0xB1,(byte) 0x1A,(byte) 0xE1};

    private static byte[] EXE_DLL = { (byte) 0x4D,(byte) 0x5A};
    private static byte[] GIF = { (byte) 0x47,(byte) 0x49,(byte) 0x46,(byte) 0x38};
    private static byte[] ICO = { (byte) 0x0,(byte) 0x0,(byte) 0x1,(byte) 0x0};
    private static byte[] JPG = { (byte) 0xFF,(byte) 0xD8,(byte) 0xFF};
    private static byte[] MP3 = { (byte) 0xFF,(byte) 0xFB,(byte) 0x30};
    private static byte[] OGG = { (byte) 0x4F,(byte) 0x67,(byte) 0x67,(byte) 0x53,(byte) 0x0,(byte) 0x2,(byte) 0x0,(byte) 0x0,(byte) 0x0,(byte) 0x0,(byte) 0x0,(byte) 0x0,(byte) 0x0,(byte) 0x0};
    private static byte[] PDF = { (byte) 0x25,(byte) 0x50,(byte) 0x44,(byte) 0x46,(byte) 0x2D,(byte) 0x31,(byte) 0x2E};
    private static byte[] PNG = { (byte) 0x89,(byte) 0x50,(byte) 0x4E,(byte) 0x47,(byte) 0xD,(byte) 0xA,(byte) 0x1A,(byte) 0xA,(byte) 0x0,(byte) 0x0,(byte) 0x0,(byte) 0xD,(byte) 0x49,(byte) 0x48,(byte) 0x44,(byte) 0x52};
    private static byte[] RAR = { (byte) 0x52,(byte) 0x61,(byte) 0x72,(byte) 0x21,(byte) 0x1A,(byte) 0x7,(byte) 0x0};
    private static byte[] SWF = { (byte) 0x46,(byte) 0x57,(byte) 0x53};
    private static byte[] TIFF = { (byte) 0x49,(byte) 0x49,(byte) 0x2A,(byte) 0x0};
    private static byte[] TORRENT = { (byte) 0x64,(byte) 0x38,(byte) 0x3A,(byte) 0x61,(byte) 0x6E,(byte) 0x6E,(byte) 0x6F,(byte) 0x75,(byte) 0x6E,(byte) 0x63,(byte) 0x65};
    private static byte[] TTF = { (byte) 0x0,(byte) 0x1,(byte) 0x0,(byte) 0x0,(byte) 0x0};
    private static byte[] WAV_AVI = { (byte) 0x52,(byte) 0x49,(byte) 0x46,(byte) 0x46};
    private static byte[] WMV_WMA = { (byte) 0x30,(byte) 0x26,(byte) 0xB2,(byte) 0x75,(byte) 0x8E,(byte) 0x66,(byte) 0xCF,(byte) 0x11,(byte) 0xA6,(byte) 0xD9,(byte) 0x0,(byte) 0xAA,(byte) 0x0,(byte) 0x62,(byte) 0xCE,(byte) 0x6C};
    private static byte[] ZIP_DOCX = { (byte) 0x50,(byte) 0x4B,(byte) 0x3,(byte) 0x4};

    public static String getMimeType(byte[] file, String extension)
    {

        String mime = "application/octet-stream"; //DEFAULT UNKNOWN MIME TYPE
        //Get the MIME Type
        if (Arrays.equals(BMP, take(file, BMP.length)))
        {
            mime = "image/bmp";
        }
        else if (Arrays.equals(DOC, take(file, DOC.length)))
        {
            mime = "application/msword";
        }
        else if (Arrays.equals(EXE_DLL, take(file, EXE_DLL.length)))
        {
            mime = "application/x-msdownload"; //both use same mime type
        }
        else if (Arrays.equals(GIF, take(file, GIF.length)))
        {
            mime = "image/gif";
        }
        else if (Arrays.equals(ICO, take(file, ICO.length)))
        {
            mime = "image/x-icon";
        }
        else if (Arrays.equals(JPG, take(file, JPG.length)))
        {
            mime = "image/jpeg";
        }
        else if (Arrays.equals(MP3, take(file, MP3.length)))
        {
            mime = "audio/mpeg";
        }
        else if (Arrays.equals(OGG, take(file, OGG.length)))
        {
            if (extension == "OGX")
            {
                mime = "application/ogg";
            }
            else if (extension == "OGA")
            {
                mime = "audio/ogg";
            }
            else
            {
                mime = "video/ogg";
            }
        }
        else if (Arrays.equals(PDF, take(file, PDF.length)))
        {
            mime = "application/pdf";
        }
        else if (Arrays.equals(PNG, take(file, PNG.length)))
        {
            mime = "image/png";
        }
        else if (Arrays.equals(RAR, take(file, RAR.length)))
        {
            mime = "application/x-rar-compressed";
        }
        else if (Arrays.equals(SWF, take(file, SWF.length)))
        {
            mime = "application/x-shockwave-flash";
        }
        else if (Arrays.equals(TIFF, take(file, TIFF.length)))
        {
            mime = "image/tiff";
        }
        else if (Arrays.equals(TORRENT, take(file, TORRENT.length)))
        {
            mime = "application/x-bittorrent";
        }
        else if (Arrays.equals(TTF, take(file, TTF.length)))
        {
            mime = "application/x-font-ttf";
        }
        else if (Arrays.equals(WAV_AVI, take(file, WAV_AVI.length)))
        {
            mime = extension == "AVI" ? "video/x-msvideo" : "audio/x-wav";
        }
        else if (Arrays.equals(WMV_WMA, take(file, WMV_WMA.length)))
        {
            mime = extension == "WMA" ? "audio/x-ms-wma" : "video/x-ms-wmv";
        }
        else if (Arrays.equals(ZIP_DOCX, take(file, ZIP_DOCX.length)))
        {
            mime = extension == "DOCX" ? "application/vnd.openxmlformats-officedocument.wordprocessingml.document" : "application/x-zip-compressed";
        }

        return mime;
    }
    
    private static byte[] take(byte[] array, int numBytes) {
    	byte[] arr = new byte[numBytes];
    	System.arraycopy(array, 0, arr, 0, numBytes);
    	return arr;
    }
}