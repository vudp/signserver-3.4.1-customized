package com.lowagie.text.pdf;

import com.lowagie.text.pdf.interfaces.IAccessibleElement;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.UUID;

public class PdfPTableFooter extends PdfPTableBody {

    protected PdfName role = PdfName.TFOOT;

    public PdfPTableFooter() {
        super();
    }

    public PdfName getRole() {
        return role;
    }

    public void setRole(final PdfName role) {
        this.role = role;
    }

}
