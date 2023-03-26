package cn.aotcloud.smcrypto;

public class Sm2KeyPair {

	private byte[] privateKey;
	
	private byte[] publicKey;

	public Sm2KeyPair(byte[] privateKey, byte[] publicKey) {
		this.privateKey = privateKey;
		this.publicKey = publicKey;
	}

	/**
	 * @return	返回私钥二进制字节码
	 */
	public byte[] getPrivateKey() {
		return privateKey;
	}

	/**
	 * @return	返回私钥二进制字节码
	 */
	public byte[] getPublicKey() {
		return publicKey;
	}
}
