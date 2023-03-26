package cn.aotcloud.smcrypto.util;

import java.io.UnsupportedEncodingException;

/**
 * 16进制与字节码转换工具
 * @author bgu
 *
 */
public class ByteUtils {

	private static final String HEX_STRING_MAPPING = "0123456789ABCDEF";
	
	public static final String CHARSET_NAME = "UTF-8";
	
	/**
	 * 字节码转为大写16进制串
	 * @param bytes
	 * @return
	 */
	public static String bytesToHex(byte[] bytes){
		if (bytes == null) {
			return null;
		}
        if (bytes.length <= 0){
            return "";
        }
		StringBuilder stringBuilder = new StringBuilder("");
        for (byte unit : bytes) {
            int unitInt = unit & 0xFF;
            String unitHex = Integer.toHexString(unitInt);
            if (unitHex.length() < 2) {
                stringBuilder.append(0);
            }
            stringBuilder.append(unitHex);
        }
		return stringBuilder.toString().toUpperCase();
	}
	
	/**
	 * 16进制串转为字节码
	 * @param hexString
	 * @return
	 */
	public static byte[] hexToBytes(String hexString) {
		if (hexString == null) {
			return null;
		}
        if (hexString.length() <= 0){
            return new byte[0];
        }
		hexString = hexString.toUpperCase();
		int length = hexString.length() / 2;
		char[] hexChars = hexString.toCharArray();
		byte[] result = new byte[length];
		for (int i = 0; i < length; i++) {
			int step = i * 2;
			result[i] = (byte) (charToByte(hexChars[step]) << 4 | charToByte(hexChars[step + 1]));
		}
		return result;
	}
	
	/**
	 * 字节码转为字符串
	 * @param bytes
	 * @return
	 */
	public static String bytesToString(byte[] bytes) {
		try {
			return new String(bytes, CHARSET_NAME);
		} catch (UnsupportedEncodingException e) {
			return null;
		}
	}
	
	/**
	 * 字符串转为字节码转
	 * @param str
	 * @return
	 */
	public static byte[] stringToBytes(String str) {
		try {
			return str.getBytes(CHARSET_NAME);
		} catch (UnsupportedEncodingException e) {
			return null;
		}
	}

	/**
	 * 16进制串转为字符串
	 * @param hexString
	 * @return
	 */
	public static String hexToString(String hexString) {
		return bytesToString(hexToBytes(hexString));
	}
	
	/**
	 * 字符串转为16进制串
	 * @param str
	 * @return
	 */
	public static String stringToHex(String str) {
		return bytesToHex(stringToBytes(str));
	}
	
	/**
	 * 字符转为字节
	 * @param c
	 * @return
	 */
	private static byte charToByte(char c) {
		return (byte) HEX_STRING_MAPPING.indexOf(c);
	}
}
