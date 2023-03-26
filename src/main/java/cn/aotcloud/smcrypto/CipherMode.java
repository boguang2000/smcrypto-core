package cn.aotcloud.smcrypto;

public enum CipherMode {
	
	C1C2C3(0), C1C3C2(1);
	
	private final int value;

    private CipherMode(int value) {
        this.value = value;
    }

    public int getValue() {
        return value;
    }
}
