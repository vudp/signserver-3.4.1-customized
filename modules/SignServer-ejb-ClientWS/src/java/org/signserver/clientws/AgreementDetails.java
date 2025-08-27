package org.signserver.clientws;

public class AgreementDetails {

    private String personName;
    private String organization;
    private String organizationUnit;
    private String title;
    private String email;
    private String telephoneNumber;
    private String location;
    private String stateOrProvince;
    private String country;
    private String personalId;
    private String passportId;
    private String taxId;
    private String budgetId;
    
    private byte[] applicationForm;
    private byte[] requestForm;
    private byte[] authorizeLetter;
    private byte[] photoIDCard;
    private byte[] photoActivityDeclaration;
    private byte[] photoAuthorizeDelegate;

    public byte[] getApplicationForm() {
        return applicationForm;
    }

    public void setApplicationForm(byte[] applicationForm) {
        this.applicationForm = applicationForm;
    }

    public byte[] getAuthorizeLetter() {
        return authorizeLetter;
    }

    public void setAuthorizeLetter(byte[] authorizeLetter) {
        this.authorizeLetter = authorizeLetter;
    }

    public String getBudgetId() {
        return budgetId;
    }

    public void setBudgetId(String budgetId) {
        this.budgetId = budgetId;
    }

    public String getCountry() {
        return country;
    }

    public void setCountry(String country) {
        this.country = country;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getLocation() {
        return location;
    }

    public void setLocation(String location) {
        this.location = location;
    }

    public String getOrganization() {
        return organization;
    }

    public void setOrganization(String organization) {
        this.organization = organization;
    }

    public String getOrganizationUnit() {
        return organizationUnit;
    }

    public void setOrganizationUnit(String organizationUnit) {
        this.organizationUnit = organizationUnit;
    }

    public String getPassportId() {
        return passportId;
    }

    public void setPassportId(String passportId) {
        this.passportId = passportId;
    }

    public String getPersonName() {
        return personName;
    }

    public void setPersonName(String personName) {
        this.personName = personName;
    }

    public String getPersonalId() {
        return personalId;
    }

    public void setPersonalId(String personalId) {
        this.personalId = personalId;
    }

    public byte[] getPhotoActivityDeclaration() {
        return photoActivityDeclaration;
    }

    public void setPhotoActivityDeclaration(byte[] photoActivityDeclaration) {
        this.photoActivityDeclaration = photoActivityDeclaration;
    }

    public byte[] getPhotoAuthorizeDelegate() {
        return photoAuthorizeDelegate;
    }

    public void setPhotoAuthorizeDelegate(byte[] photoAuthorizeDelegate) {
        this.photoAuthorizeDelegate = photoAuthorizeDelegate;
    }

    public byte[] getPhotoIDCard() {
        return photoIDCard;
    }

    public void setPhotoIDCard(byte[] photoIDCard) {
        this.photoIDCard = photoIDCard;
    }

    public byte[] getRequestForm() {
        return requestForm;
    }

    public void setRequestForm(byte[] requestForm) {
        this.requestForm = requestForm;
    }

    public String getStateOrProvince() {
        return stateOrProvince;
    }

    public void setStateOrProvince(String stateOrProvince) {
        this.stateOrProvince = stateOrProvince;
    }

    public String getTaxId() {
        return taxId;
    }

    public void setTaxId(String taxId) {
        this.taxId = taxId;
    }

    public String getTelephoneNumber() {
        return telephoneNumber;
    }

    public void setTelephoneNumber(String telephoneNumber) {
        this.telephoneNumber = telephoneNumber;
    }

    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        this.title = title;
    }
    
    
}