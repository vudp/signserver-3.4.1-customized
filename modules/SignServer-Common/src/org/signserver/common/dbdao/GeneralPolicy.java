package org.signserver.common.dbdao;


public class GeneralPolicy {

	
    private int generalPolicyID;
    private int frontExpirationNotificationDay;
    private int frontMaxRetry;
    private int frontFreezeTime;
    private int frontOTPMaxEvent;
    private int frontOTPMaxInterval;
    private int frontOTPNumDigits;
    private int frontOTPTimeOut;
    private int frontHAIntervalCheck;
    private boolean frontIsForgotEmailSignserver;
    private boolean frontIsHAEmail;
    private boolean frontIsHASMS;
    private boolean frontIsHAReSent;
    private boolean frontIsAccessFunction;
    private boolean frontIsOptimized;
    private String frontDefaultPassSignserver;
    private boolean frontAgreementActivationAutoLink;
    private boolean frontAgreementCreationAutoLink;
    private boolean frontIsRandomSignServerPassword;
    private boolean frontIsNotifySignServerPasswordByEmail;
    private boolean frontIsNotifySignServerCertificateByEmail;
    

    public int getGeneralPolicyID() {
        return generalPolicyID;
    }

    public void setGeneralPolicyID(int generalPolicyID) {
        this.generalPolicyID = generalPolicyID;
    }

    public int getFrontExpirationNotificationDay() {
        return frontExpirationNotificationDay;
    }

    public void setFrontExpirationNotificationDay(int frontExpirationNotificationDay) {
        this.frontExpirationNotificationDay = frontExpirationNotificationDay;
    }

    public int getFrontMaxRetry() {
        return frontMaxRetry;
    }

    public void setFrontMaxRetry(int frontMaxRetry) {
        this.frontMaxRetry = frontMaxRetry;
    }

    public int getFrontFreezeTime() {
        return frontFreezeTime;
    }

    public void setFrontFreezeTime(int frontFreezeTime) {
        this.frontFreezeTime = frontFreezeTime;
    }

    public int getFrontOTPMaxEvent() {
        return frontOTPMaxEvent;
    }

    public void setFrontOTPMaxEvent(int frontOTPMaxEvent) {
        this.frontOTPMaxEvent = frontOTPMaxEvent;
    }

    public int getFrontOTPMaxInterval() {
        return frontOTPMaxInterval;
    }

    public void setFrontOTPMaxInterval(int frontOTPMaxInterval) {
        this.frontOTPMaxInterval = frontOTPMaxInterval;
    }

    public int getFrontOTPNumDigits() {
        return frontOTPNumDigits;
    }

    public void setFrontOTPNumDigits(int frontOTPNumDigits) {
        this.frontOTPNumDigits = frontOTPNumDigits;
    }

    public int getFrontOTPTimeOut() {
        return frontOTPTimeOut;
    }

    public void setFrontOTPTimeOut(int frontOTPTimeOut) {
        this.frontOTPTimeOut = frontOTPTimeOut;
    }

    public int getFrontHAIntervalCheck() {
        return frontHAIntervalCheck;
    }

    public void setFrontHAIntervalCheck(int frontHAIntervalCheck) {
        this.frontHAIntervalCheck = frontHAIntervalCheck;
    }

    public boolean isFrontIsForgotEmailSignserver() {
        return frontIsForgotEmailSignserver;
    }

    public void setFrontIsForgotEmailSignserver(boolean frontIsForgotEmailSignserver) {
        this.frontIsForgotEmailSignserver = frontIsForgotEmailSignserver;
    }

    public boolean isFrontIsHAEmail() {
        return frontIsHAEmail;
    }

    public void setFrontIsHAEmail(boolean frontIsHAEmail) {
        this.frontIsHAEmail = frontIsHAEmail;
    }

    public boolean isFrontIsHASMS() {
        return frontIsHASMS;
    }

    public void setFrontIsHASMS(boolean frontIsHASMS) {
        this.frontIsHASMS = frontIsHASMS;
    }

    public boolean isFrontIsHAReSent() {
        return frontIsHAReSent;
    }

    public void setFrontIsHAReSent(boolean frontIsHAReSent) {
        this.frontIsHAReSent = frontIsHAReSent;
    }

    public boolean isFrontIsAccessFunction() {
        return frontIsAccessFunction;
    }

    public void setFrontIsAccessFunction(boolean frontIsAccessFunction) {
        this.frontIsAccessFunction = frontIsAccessFunction;
    }

    public boolean isFrontIsOptimized() {
        return frontIsOptimized;
    }

    public void setFrontIsOptimized(boolean frontIsOptimized) {
        this.frontIsOptimized = frontIsOptimized;
    }

    public String getFrontDefaultPassSignserver() {
        return frontDefaultPassSignserver;
    }

    public void setFrontDefaultPassSignserver(String frontDefaultPassSignserver) {
        this.frontDefaultPassSignserver = frontDefaultPassSignserver;
    }
    
    public boolean isFrontAgreementActivationAutoLink() {
        return frontAgreementActivationAutoLink;
    }

    public void setFrontAgreementActivationAutoLink(boolean frontAgreementActivationAutoLink) {
        this.frontAgreementActivationAutoLink = frontAgreementActivationAutoLink;
    }

    public boolean isFrontAgreementCreationAutoLink() {
        return frontAgreementCreationAutoLink;
    }

    public void setFrontAgreementCreationAutoLink(boolean frontAgreementCreationAutoLink) {
        this.frontAgreementCreationAutoLink = frontAgreementCreationAutoLink;
    }

    public boolean isFrontIsRandomSignServerPassword() {
        return frontIsRandomSignServerPassword;
    }

    public void setFrontIsRandomSignServerPassword(boolean frontIsRandomSignServerPassword) {
        this.frontIsRandomSignServerPassword = frontIsRandomSignServerPassword;
    }

    public boolean isFrontIsNotifySignServerCertificateByEmail() {
        return frontIsNotifySignServerCertificateByEmail;
    }

    public void setFrontIsNotifySignServerCertificateByEmail(boolean frontIsNotifySignServerCertificateByEmail) {
        this.frontIsNotifySignServerCertificateByEmail = frontIsNotifySignServerCertificateByEmail;
    }

    public boolean isFrontIsNotifySignServerPasswordByEmail() {
        return frontIsNotifySignServerPasswordByEmail;
    }

    public void setFrontIsNotifySignServerPasswordByEmail(boolean frontIsNotifySignServerPasswordByEmail) {
        this.frontIsNotifySignServerPasswordByEmail = frontIsNotifySignServerPasswordByEmail;
    }
    
    
    
}