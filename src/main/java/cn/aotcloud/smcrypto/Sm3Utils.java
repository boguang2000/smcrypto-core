package cn.aotcloud.smcrypto;

import cn.aotcloud.smcrypto.exception.InvalidSourceDataException;
import cn.aotcloud.smcrypto.util.ByteUtils;
import cn.aotcloud.smcrypto.util.StringUtils;

public class Sm3Utils {
	
	protected static final Sm3Digest sm3Digest = new Sm3Digest();

	/**
	 * 字节码SM3加密
	 * @param sourceText	明文字节码
	 * @return 加密字节码
	 * @throws InvalidSourceDataException 
	 */
	public static byte[] encryptFromData(byte[] sourceData) throws InvalidSourceDataException {
		if(sourceData==null || sourceData.length == 0) {
			throw new InvalidSourceDataException("[SM3:encryptFromData]invalid sourceData");
		}
		byte[] encData = sm3Digest.getEncrypted(sourceData);
		return encData;
	}
	
	/**
	 * 字符串SM3加密
	 * @param sourceHex		明文16进制串
	 * @return 16进制加密串
	 * @throws InvalidSourceDataException 
	 */
	public static String encryptFromHex(String sourceHex) throws InvalidSourceDataException {
		if(StringUtils.isEmpty(sourceHex)) {
			throw new InvalidSourceDataException("[SM3:encryptFromHex]invalid sourceData");
		}
		byte[] sourceData = ByteUtils.hexToBytes(sourceHex);
		byte[] encData = sm3Digest.getEncrypted(sourceData);
		return ByteUtils.bytesToHex(encData);
	}
	
	/**
	 * 字符串SM3加密
	 * @param sourceText	明文字符串
	 * @return 16进制加密串
	 * @throws InvalidSourceDataException 
	 */
	public static String encryptFromText(String sourceText) throws InvalidSourceDataException {
		if(StringUtils.isEmpty(sourceText)) {
			throw new InvalidSourceDataException("[SM3:encryptFromText]invalid sourceData");
		}
		byte[] sourceData = ByteUtils.stringToBytes(sourceText);
		byte[] encData = sm3Digest.getEncrypted(sourceData);
		return ByteUtils.bytesToHex(encData);
	}
}
