package org.signserver.common.dbdao;

public class P11Info {
	private int p11InfoId;
	private int slotId;
	private String module;
	private String pin;
	private String sopin;
	private String level;
	
	public int getP11InfoId() {
        return p11InfoId;
    }

    public void setP11InfoId(int p11InfoId) {
        this.p11InfoId = p11InfoId;
    }
	
	public int getSlotId() {
        return slotId;
    }

    public void setSlotId(int slotId) {
        this.slotId = slotId;
    }

    public String getModule() {
        return module;
    }

    public void setModule(String module) {
        this.module = module;
    }

    public String getPin() {
        return pin;
    }

    public void setPin(String pin) {
        this.pin = pin;
    }

    public String getLevel() {
        return level;
    }

    public void setLevel(String level) {
        this.level = level;
    }
    
    public String getSopin() {
        return sopin;
    }

    public void setSopin(String sopin) {
        this.sopin = sopin;
    }
}