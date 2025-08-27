/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.signserver.common.dbdao;
/**
 *
 * @author PHUONGVU
 */
public class CertTemplate {
    private String attrCode;
    private String prefix;

    public CertTemplate() {
    }
    
    

    public CertTemplate(String attrCode, String prefix) {
        this.attrCode = attrCode;
        this.prefix = prefix;
    }

    public String getAttrCode() {
        return attrCode;
    }

    public void setAttrCode(String attrCode) {
        this.attrCode = attrCode;
    }

    public String getPrefix() {
        return prefix;
    }

    public void setPrefix(String prefix) {
        this.prefix = prefix;
    }
}
