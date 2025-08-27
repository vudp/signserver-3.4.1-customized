package org.signserver.common.util;
import java.util.Date;

/**
 *
 * @author PHUONGVU
 */
public class AgreementObject {
	private String user;
    private String remark;
    private String channel;
    private String agreementStatus;

    private boolean isOtpSms;
    private String otpSms;
    private boolean isOtpSmsLinked;

    private boolean isOtpEmail;
    private String otpEmail;
    private boolean isOtpEmailLinked;

    private boolean isOtpHardware;
    private String otpHardware;
    private boolean isOtpHardwareLinked;
    
    private boolean isOtpSoftware;
    private boolean isOtpSoftwareLinked;

    private boolean isPki;
    private String certificate;
    private String tpkiThumbPrint;
    private boolean isTPKILinked;

    private boolean isLcdPki;
    private String lcdCertificate;
    private String lpkiThumbPrint;
    private boolean isLPKILinked;

    private boolean isSimPKI;
    private String simCertificate;
    private String pkiSim;
    private String wpkiThumbPrint;
    private boolean isWPKILinked;

    private boolean isSignserver;
    private String sCertificate;
    private String spkiThumbPrint;
    private boolean isSPKILinked;

    private Date createdDate;
    private Date effectiveDate;
    private Date expiredDate;

    public String getUser() {
        return user;
    }

    public void setUser(String user) {
        this.user = user;
    }

    public String getRemark() {
        return remark;
    }

    public void setRemark(String remark) {
        this.remark = remark;
    }

    public String getChannel() {
        return channel;
    }

    public void setChannel(String channel) {
        this.channel = channel;
    }

    public String getAgreementStatus() {
        return agreementStatus;
    }

    public void setAgreementStatus(String agreementStatus) {
        this.agreementStatus = agreementStatus;
    }

    public boolean isIsOtpSms() {
        return isOtpSms;
    }

    public void setIsOtpSms(boolean isOtpSms) {
        this.isOtpSms = isOtpSms;
    }

    public String getOtpSms() {
        return otpSms;
    }

    public void setOtpSms(String otpSms) {
        this.otpSms = otpSms;
    }

    public boolean isIsOtpSmsLinked() {
        return isOtpSmsLinked;
    }

    public void setIsOtpSmsLinked(boolean isOtpSmsLinked) {
        this.isOtpSmsLinked = isOtpSmsLinked;
    }

    public boolean isIsOtpEmail() {
        return isOtpEmail;
    }

    public void setIsOtpEmail(boolean isOtpEmail) {
        this.isOtpEmail = isOtpEmail;
    }

    public String getOtpEmail() {
        return otpEmail;
    }

    public void setOtpEmail(String otpEmail) {
        this.otpEmail = otpEmail;
    }

    public boolean isIsOtpEmailLinked() {
        return isOtpEmailLinked;
    }

    public void setIsOtpEmailLinked(boolean isOtpEmailLinked) {
        this.isOtpEmailLinked = isOtpEmailLinked;
    }

    public boolean isIsOtpHardware() {
        return isOtpHardware;
    }

    public void setIsOtpHardware(boolean isOtpHardware) {
        this.isOtpHardware = isOtpHardware;
    }

    public String getOtpHardware() {
        return otpHardware;
    }

    public void setOtpHardware(String otpHardware) {
        this.otpHardware = otpHardware;
    }

    public boolean isIsOtpHardwareLinked() {
        return isOtpHardwareLinked;
    }

    public void setIsOtpHardwareLinked(boolean isOtpHardwareLinked) {
        this.isOtpHardwareLinked = isOtpHardwareLinked;
    }

    public boolean isIsOtpSoftware() {
        return isOtpSoftware;
    }

    public void setIsOtpSoftware(boolean isOtpSoftware) {
        this.isOtpSoftware = isOtpSoftware;
    }

    public boolean isIsOtpSoftwareLinked() {
        return isOtpSoftwareLinked;
    }

    public void setIsOtpSoftwareLinked(boolean isOtpSoftwareLinked) {
        this.isOtpSoftwareLinked = isOtpSoftwareLinked;
    }

    public boolean isIsPki() {
        return isPki;
    }

    public void setIsPki(boolean isPki) {
        this.isPki = isPki;
    }

    public String getCertificate() {
        return certificate;
    }

    public void setCertificate(String certificate) {
        this.certificate = certificate;
    }

    public String getTpkiThumbPrint() {
        return tpkiThumbPrint;
    }

    public void setTpkiThumbPrint(String tpkiThumbPrint) {
        this.tpkiThumbPrint = tpkiThumbPrint;
    }

    public boolean isIsTPKILinked() {
        return isTPKILinked;
    }

    public void setIsTPKILinked(boolean isTPKILinked) {
        this.isTPKILinked = isTPKILinked;
    }

    public boolean isIsLcdPki() {
        return isLcdPki;
    }

    public void setIsLcdPki(boolean isLcdPki) {
        this.isLcdPki = isLcdPki;
    }

    public String getLcdCertificate() {
        return lcdCertificate;
    }

    public void setLcdCertificate(String lcdCertificate) {
        this.lcdCertificate = lcdCertificate;
    }

    public String getLpkiThumbPrint() {
        return lpkiThumbPrint;
    }

    public void setLpkiThumbPrint(String lpkiThumbPrint) {
        this.lpkiThumbPrint = lpkiThumbPrint;
    }

    public boolean isIsLPKILinked() {
        return isLPKILinked;
    }

    public void setIsLPKILinked(boolean isLPKILinked) {
        this.isLPKILinked = isLPKILinked;
    }

    public boolean isIsSimPKI() {
        return isSimPKI;
    }

    public void setIsSimPKI(boolean isSimPKI) {
        this.isSimPKI = isSimPKI;
    }

    public String getSimCertificate() {
        return simCertificate;
    }

    public void setSimCertificate(String simCertificate) {
        this.simCertificate = simCertificate;
    }

    public String getPkiSim() {
        return pkiSim;
    }

    public void setPkiSim(String pkiSim) {
        this.pkiSim = pkiSim;
    }

    public String getWpkiThumbPrint() {
        return wpkiThumbPrint;
    }

    public void setWpkiThumbPrint(String wpkiThumbPrint) {
        this.wpkiThumbPrint = wpkiThumbPrint;
    }

    public boolean isIsWPKILinked() {
        return isWPKILinked;
    }

    public void setIsWPKILinked(boolean isWPKILinked) {
        this.isWPKILinked = isWPKILinked;
    }

    public boolean isIsSignserver() {
        return isSignserver;
    }

    public void setIsSignserver(boolean isSignserver) {
        this.isSignserver = isSignserver;
    }

    public String getsCertificate() {
        return sCertificate;
    }

    public void setsCertificate(String sCertificate) {
        this.sCertificate = sCertificate;
    }

    public String getSpkiThumbPrint() {
        return spkiThumbPrint;
    }

    public void setSpkiThumbPrint(String spkiThumbPrint) {
        this.spkiThumbPrint = spkiThumbPrint;
    }

    public boolean isIsSPKILinked() {
        return isSPKILinked;
    }

    public void setIsSPKILinked(boolean isSPKILinked) {
        this.isSPKILinked = isSPKILinked;
    }

    public Date getCreatedDate() {
        return createdDate;
    }

    public void setCreatedDate(Date createdDate) {
        this.createdDate = createdDate;
    }

    public Date getEffectiveDate() {
        return effectiveDate;
    }

    public void setEffectiveDate(Date effectiveDate) {
        this.effectiveDate = effectiveDate;
    }

    public Date getExpiredDate() {
        return expiredDate;
    }

    public void setExpiredDate(Date expiredDate) {
        this.expiredDate = expiredDate;
    }
}