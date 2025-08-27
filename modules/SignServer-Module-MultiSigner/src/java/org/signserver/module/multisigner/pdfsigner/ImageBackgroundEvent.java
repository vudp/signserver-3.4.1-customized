package org.signserver.module.multisigner.pdfsigner;

import com.itextpdf.text.DocumentException;
import com.itextpdf.text.Image;
import com.itextpdf.text.Rectangle;
import com.itextpdf.text.pdf.PdfContentByte;
import com.itextpdf.text.pdf.PdfPCell;
import com.itextpdf.text.pdf.PdfPCellEvent;
import com.itextpdf.text.pdf.PdfPTable;

/*
import com.lowagie.text.DocumentException;
import com.lowagie.text.ExceptionConverter;
import com.lowagie.text.Image;
import com.lowagie.text.Rectangle;
import com.lowagie.text.pdf.PdfContentByte;
import com.lowagie.text.pdf.PdfPCell;
import com.lowagie.text.pdf.PdfPCellEvent;
import com.lowagie.text.pdf.PdfPTable;
*/




public class ImageBackgroundEvent implements PdfPCellEvent {
 
    protected Image image;
 
    public ImageBackgroundEvent(Image image) {
        this.image = image;
    }
 
    public void cellLayout(PdfPCell cell, Rectangle position, PdfContentByte[] canvases) {
    	image.scaleToFit(position.getWidth(), position.getHeight());
    	image.setAbsolutePosition(position.getLeft() + (position.getWidth() - image.getScaledWidth()) / 2,
                position.getBottom() + (position.getHeight() - image.getScaledHeight()) / 2);
        PdfContentByte canvas = canvases[PdfPTable.BACKGROUNDCANVAS];
        try {
            canvas.addImage(image);
        } catch (DocumentException ex) {
            // do nothing
        }
    }
}