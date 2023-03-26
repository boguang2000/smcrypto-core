package cn.aotcloud.smcrypto;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.util.logging.Logger;

import cn.aotcloud.smcrypto.exception.InvalidContextException;
import cn.aotcloud.smcrypto.exception.InvalidCryptoDataException;
import cn.aotcloud.smcrypto.exception.InvalidIvException;
import cn.aotcloud.smcrypto.exception.InvalidKeyException;
import cn.aotcloud.smcrypto.exception.InvalidSourceDataException;
import cn.aotcloud.smcrypto.util.ByteUtils;
import cn.aotcloud.smcrypto.util.LoggerFactory;
import cn.aotcloud.smcrypto.util.StringUtils;

public class Sm4Utils {
	
	/**
	 * ECB模式静态工具子类
	 * @author bgu
	 */
	public static class ECB {
		
		private static final Logger logger = LoggerFactory.getLogger(ECB.class.getName());
		
		/**
		 * SM4_ECB模式字符串加密
		 * @param plainText	明文字符串
		 * @param keyHex	密钥十六进制串
		 * @return 密文16进制串
		 * @throws InvalidCryptoDataException 
		 * @throws InvalidSourceDataException 
		 */
		public static String encryptFromText(String plainText, String keyHex) throws InvalidKeyException, InvalidSourceDataException {
			return encryptFromText(plainText, keyHex, true);
		}
		
		/**
		 * SM4_ECB模式字符串加密
		 * @param plainText	明文字符串
		 * @param keyHex	密钥十六进制串
		 * @param isPadding	是否填充
		 * @return 密文16进制串
		 * @throws InvalidKeyException 
		 * @throws InvalidSourceDataException 
		 */
		public static String encryptFromText(String plainText, String keyHex, boolean isPadding) throws InvalidKeyException, InvalidSourceDataException {
			if(StringUtils.isEmpty(plainText)) {
				throw new InvalidSourceDataException("[SM4_ECB:encryptFromText]invalid plainText");
			}
			if(StringUtils.length(keyHex) != 32) {
				throw new InvalidKeyException("[SM4_ECB:encryptFromText]invalid keyHex");
			}
			byte[] plainBytes = ByteUtils.stringToBytes(plainText);
			byte[] keyBytes	= ByteUtils.hexToBytes(keyHex);
			byte[] encrypted= encryptFromData(plainBytes, keyBytes, isPadding);
			return ByteUtils.bytesToHex(encrypted);
		}
		
		/**
		 * SM4_ECB模式十六进制加密
		 * @param plainHex	明文十六进制串
		 * @param keyHex	密钥十六进制串
		 * @return 密文16进制串
		 * @throws InvalidKeyException 
		 * @throws InvalidCryptoDataException 
		 * @throws InvalidSourceDataException 
		 */
		public static String encryptFromHex(String plainHex, String keyHex) throws InvalidKeyException, InvalidSourceDataException {
			return encryptFromHex(plainHex, keyHex, true);
		}
		
		/**
		 * SM4_ECB模式十六进制加密
		 * @param plainHex	明文十六进制串
		 * @param keyHex	密钥十六进制串
		 * @param isPadding	是否填充
		 * @return 密文16进制串
		 * @throws InvalidKeyException 
		 * @throws InvalidSourceDataException 
		 */
		public static String encryptFromHex(String plainHex, String keyHex, boolean isPadding) throws InvalidKeyException, InvalidSourceDataException {
			if(StringUtils.isEmpty(plainHex)) {
				throw new InvalidSourceDataException("[SM4_ECB:encryptFromHex]invalid plainHex");
			}
			if(StringUtils.length(keyHex) != 32) {
				throw new InvalidKeyException("[SM4_ECB:encryptFromHex]invalid keyHex");
			}
			byte[] plainBytes = ByteUtils.hexToBytes(plainHex);
			byte[] keyBytes	= ByteUtils.hexToBytes(keyHex);
			byte[] encrypted= encryptFromData(plainBytes, keyBytes, isPadding);
			return ByteUtils.bytesToHex(encrypted);
		}
		
		/**
		 * SM4_ECB模式流加密
		 * @param is		输入流（明文输入）
		 * @param os		输出流（密文输出）
		 * @param keyBytes	密钥字节码
		 * @throws IOException
		 * @throws InvalidKeyException
		 * @throws InvalidSourceDataException
		 */
		public static void encryptInputStream(InputStream is, OutputStream os, byte[] keyBytes) throws IOException, InvalidKeyException, InvalidSourceDataException {
			encryptInputStream(is, os, keyBytes, true);
		}
		
		/**
		 * SM4_ECB模式流加密
		 * @param is		输入流（明文输入）
		 * @param os		输出流（密文输出）
		 * @param keyBytes	密钥字节码
		 * @param isPadding	是否填充
		 * @throws IOException
		 * @throws InvalidKeyException
		 * @throws InvalidSourceDataException
		 */
		public static void encryptInputStream(InputStream is, OutputStream os, byte[] keyBytes, boolean isPadding) throws IOException, InvalidKeyException, InvalidSourceDataException {
			byte[] buffer = new byte[1024];
            byte[] data = null;
            byte[] cipherBytes = null;
            int length;
            int point = 0;
            while ((length = is.read(buffer)) != -1) {
            	if(point > 0 && data != null) {
            		cipherBytes = encryptFromData(data, keyBytes, false);
            		os.write(cipherBytes);
            	}
            	data = new byte[length];
            	System.arraycopy(buffer, 0, data, 0, length);
            	point ++;
            }
            cipherBytes = encryptFromData(data, keyBytes, isPadding);
    		os.write(cipherBytes);
    		buffer = null;
    		data = null;
    		cipherBytes = null;
		}
		
		/**
		 * SM4_ECB模式字节码加密
		 * @param plainBytes明文字节码
		 * @param keyBytes	密钥字节码
		 * @return 密文字节码
		 * @throws InvalidKeyException 
		 * @throws InvalidSourceDataException 
		 */
		public static byte[] encryptFromData(byte[] plainBytes, byte[] keyBytes) throws InvalidKeyException, InvalidSourceDataException {
			return encryptFromData(plainBytes, keyBytes, true);
		}
		
		/**
		 * SM4_ECB模式字节码加密
		 * @param plainBytes明文字节码
		 * @param keyBytes	密钥字节码
		 * @param isPadding	是否填充
		 * @return
		 * @throws InvalidKeyException 
		 * @throws InvalidSourceDataException 
		 */
		public static byte[] encryptFromData(byte[] plainBytes, byte[] keyBytes, boolean isPadding) throws InvalidKeyException, InvalidSourceDataException {
			if(plainBytes==null || plainBytes.length == 0) {
				throw new InvalidSourceDataException("[SM4_ECB:encryptFromData]invalid plainBytes");
			}
			if(keyBytes==null || keyBytes.length != 16) {
				throw new InvalidKeyException("[SM4_ECB:encryptFromData]invalid keyBytes");
			}
			try {
				Sm4Context ctx = new Sm4Context();
				ctx.isPadding = isPadding;
				Sm4 sm4 = new Sm4();
				sm4.sm4_setkey_enc(ctx, keyBytes);
				byte[] encrypted = sm4.sm4_crypt_ecb(ctx, plainBytes);
				return encrypted;
			} catch (InvalidContextException e) {
				logger.warning("SM4 ECB Model Encrypt InvalidContextException!");
				return null;
			} catch (IOException e) {
				logger.warning("SM4 ECB Model Encrypt IOException!");
				return null;
			}
		}
		
		/**
		 * SM4_ECB模式字符串解密
		 * @param cipherHex	密文十六进制串
		 * @param keyHex	密钥十六进制串
		 * @return 明文字符串
		 * @throws InvalidCryptoDataException 
		 * @throws InvalidKeyException 
		 * @throws UnsupportedEncodingException 
		 */
		public static String decryptToText(String cipherHex, String keyHex) throws InvalidCryptoDataException, InvalidKeyException {
			return decryptToText(cipherHex, keyHex, true);
		}
		
		/**
		 * SM4_ECB模式字符串解密
		 * @param cipherHex	密文十六进制串
		 * @param keyHex	密钥十六进制串
		 * @param isPadding	是否填充
		 * @return 明文字符串
		 * @throws InvalidCryptoDataException 
		 * @throws InvalidKeyException 
		 * @throws UnsupportedEncodingException 
		 */
		public static String decryptToText(String cipherHex, String keyHex, boolean isPadding) throws InvalidCryptoDataException, InvalidKeyException {
			if(StringUtils.length(keyHex)==0 || cipherHex.length() % 32 != 0) {
				throw new InvalidCryptoDataException("[SM4_ECB:decryptToText]invalid cipherHex");
			}
			if(StringUtils.length(keyHex) != 32) {
				throw new InvalidKeyException("[SM4_ECB:decryptToText]invalid keyHex");
			}
			byte[] cipherBytes = ByteUtils.hexToBytes(cipherHex);
			byte[] keyBytes = ByteUtils.hexToBytes(keyHex);
			byte[] decrypted= decryptToData(cipherBytes, keyBytes, isPadding);
			return ByteUtils.bytesToString(decrypted);
		}
		
		/**
		 * SM4_ECB模式十六进制解密
		 * @param cipherHex	密文十六进制串
		 * @param keyHex	密钥十六进制串
		 * @return 明文字符串
		 * @throws InvalidCryptoDataException 
		 * @throws InvalidKeyException 
		 */
		public static String decryptToHex(String cipherHex, String keyHex) throws InvalidCryptoDataException, InvalidKeyException {
			return decryptToHex(cipherHex, keyHex, true);
		}
		
		/**
		 * SM4_ECB模式十六进制解密
		 * @param cipherHex	密文十六进制串
		 * @param keyHex	密钥十六进制串
		 * @param isPadding	是否填充
		 * @return 明文字符串
		 * @throws InvalidCryptoDataException 
		 * @throws InvalidKeyException 
		 */
		public static String decryptToHex(String cipherHex, String keyHex, boolean isPadding) throws InvalidCryptoDataException, InvalidKeyException {
			if(StringUtils.length(keyHex)==0 || cipherHex.length() % 32 != 0) {
				throw new InvalidCryptoDataException("[SM4_ECB:decryptToHex]invalid cipherHex");
			}
			if(StringUtils.length(keyHex) != 32) {
				throw new InvalidKeyException("[SM4_ECB:decryptToHex]invalid keyHex");
			}
			byte[] cipherBytes = ByteUtils.hexToBytes(cipherHex);
			byte[] keyBytes = ByteUtils.hexToBytes(keyHex);
			byte[] decrypted= decryptToData(cipherBytes, keyBytes, isPadding);
			return ByteUtils.bytesToHex(decrypted);
		}

		/**
		 * SM4_ECB模式流解密
		 * @param is		输入流（密文输入）
		 * @param os		输出流（明文输出）
		 * @param keyBytes	密钥字节码
		 * @throws IOException
		 * @throws InvalidKeyException
		 * @throws InvalidSourceDataException
		 * @throws InvalidCryptoDataException 
		 */
		public static void decryptInputStream(InputStream is, OutputStream os, byte[] keyBytes) throws IOException, InvalidKeyException, InvalidCryptoDataException {
			decryptInputStream(is, os, keyBytes, true);
		}
		
		/**
		 * SM4_ECB模式流解密
		 * @param is		输入流（密文输入）
		 * @param os		输出流（明文输出）
		 * @param keyBytes	密钥字节码
		 * @param isPadding	是否填充
		 * @throws IOException
		 * @throws InvalidKeyException
		 * @throws InvalidSourceDataException
		 * @throws InvalidCryptoDataException 
		 */
		public static void decryptInputStream(InputStream is, OutputStream os, byte[] keyBytes, boolean isPadding) throws IOException, InvalidKeyException, InvalidCryptoDataException {
			byte[] buffer = new byte[1024];
            byte[] data = null;
            byte[] plantBytes = null;
            int length;
            int point = 0;
            while ((length = is.read(buffer)) != -1) {
            	if(point > 0 && data != null) {
            		plantBytes = decryptToData(data, keyBytes, false);
            		os.write(plantBytes);
            	}
            	data = new byte[length];
            	System.arraycopy(buffer, 0, data, 0, length);
            	point ++;
            }
            plantBytes = decryptToData(data, keyBytes, isPadding);
    		os.write(plantBytes);
    		buffer = null;
    		data = null;
    		plantBytes = null;
		}
		
		/**
		 * SM4_ECB模式字节码解密
		 * @param cipherBytes	密文字节码
		 * @param keyBytes		密钥字节码
		 * @return 明文字符串
		 * @throws InvalidKeyException 
		 * @throws InvalidCryptoDataException 
		 */
		public static byte[] decryptToData(byte[] cipherBytes, byte[] keyBytes) throws InvalidKeyException, InvalidCryptoDataException {
			return decryptToData(cipherBytes, keyBytes, true);
		}
		
		/**
		 * SM4_ECB模式字节码解密
		 * @param cipherBytes	密文字节码
		 * @param keyBytes		密钥字节码
		 * @param isPadding		是否填充
		 * @return 明文字符串
		 * @throws InvalidKeyException 
		 * @throws InvalidCryptoDataException 
		 */
		public static byte[] decryptToData(byte[] cipherBytes, byte[] keyBytes, boolean isPadding) throws InvalidKeyException, InvalidCryptoDataException {
			if(cipherBytes==null || cipherBytes.length == 0 || cipherBytes.length%16 != 0) {
				throw new InvalidCryptoDataException("[SM4_ECB:decryptToData]invalid cipherBytes");
			}
			if(keyBytes==null || keyBytes.length != 16) {
				throw new InvalidKeyException("[SM4_ECB:decryptToData]invalid keyBytes");
			}
			try {
				Sm4Context ctx = new Sm4Context();
				ctx.isPadding = isPadding;
				Sm4 sm4 = new Sm4();
				sm4.sm4_setkey_dec(ctx, keyBytes);
				byte[] decrypted = sm4.sm4_crypt_ecb(ctx, cipherBytes);
				return decrypted;
			} catch (InvalidContextException e) {
				logger.warning("SM4 ECB Model Decrypt InvalidContextException!");
				return null;
			} catch (IOException e) {
				logger.warning("SM4 ECB Model Decrypt IOException!");
				return null;
			}
		}
	}

	/**
	 * CBC模式静态工具子类
	 * @author bgu
	 */
	public static class CBC {
		
		private static final Logger logger = LoggerFactory.getLogger(CBC.class.getName());
		
		/**
		 * SM4_CBC模式字符串加密
		 * @param plainText	明文字符串
		 * @param keyHex	密钥十六进制串
		 * @param ivHex		向量十六进制串
		 * @return 密文16进制串
		 * @throws InvalidKeyException 
		 * @throws InvalidSourceDataException 
		 */
		public static String encryptFromText(String plainText, String keyHex, String ivHex) throws InvalidSourceDataException, InvalidKeyException {
			return encryptFromText(plainText, keyHex, ivHex, true);
		}
		
		/**
		 * SM4_CBC模式字符串加密
		 * @param plainText	明文字符串
		 * @param keyHex	密钥十六进制串
		 * @param ivHex		向量十六进制串
		 * @param isPadding	是否填充
		 * @return 密文16进制串
		 * @throws InvalidSourceDataException 
		 * @throws InvalidKeyException 
		 */
		public static String encryptFromText(String plainText, String keyHex, String ivHex, boolean isPadding) throws InvalidSourceDataException, InvalidKeyException {
			if(StringUtils.isEmpty(plainText)) {
				throw new InvalidSourceDataException("[SM4_CBC:encryptFromText]invalid plainText");
			}
			if(StringUtils.length(keyHex) != 32) {
				throw new InvalidKeyException("[SM4_CBC:encryptFromText]invalid keyHex");
			}
			if(StringUtils.length(ivHex) != 32) {
				throw new InvalidKeyException("[SM4_CBC:encryptFromText]invalid ivHex");
			}
			byte[] plainBytes = ByteUtils.stringToBytes(plainText);
			byte[] keyBytes = ByteUtils.hexToBytes(keyHex);
			byte[] ivBytes = ByteUtils.hexToBytes(ivHex);
			byte[] encrypted = encryptFromData(plainBytes, keyBytes, ivBytes, isPadding);
			return ByteUtils.bytesToHex(encrypted);
		}
		
		/**
		 * SM4_CBC模式十六进制加密
		 * @param plainHex	明文十六进制串
		 * @param keyHex	密钥十六进制串
		 * @param ivHex		向量十六进制串
		 * @return 密文16进制串
		 * @throws InvalidKeyException 
		 * @throws InvalidSourceDataException 
		 */
		public static String encryptFromHex(String plainHex, String keyHex, String ivHex) throws InvalidSourceDataException, InvalidKeyException {
			return encryptFromHex(plainHex, keyHex, ivHex, true);
		}
		
		/**
		 * SM4_CBC模式十六进制加密
		 * @param plainHex	明文十六进制串
		 * @param keyHex	密钥十六进制串
		 * @param ivHex		向量十六进制串
		 * @param isPadding	是否填充
		 * @return 密文16进制串
		 * @throws InvalidSourceDataException 
		 * @throws InvalidKeyException 
		 */
		public static String encryptFromHex(String plainHex, String keyHex, String ivHex, boolean isPadding) throws InvalidSourceDataException, InvalidKeyException {
			if(StringUtils.isEmpty(plainHex)) {
				throw new InvalidSourceDataException("[SM4_CBC:encryptFromHex]invalid plainHex");
			}
			if(StringUtils.length(keyHex) != 32) {
				throw new InvalidKeyException("[SM4_CBC:encryptFromHex]invalid keyHex");
			}
			if(StringUtils.length(ivHex) != 32) {
				throw new InvalidKeyException("[SM4_CBC:encryptFromHex]invalid ivHex");
			}
			byte[] plainBytes = ByteUtils.hexToBytes(plainHex);
			byte[] keyBytes = ByteUtils.hexToBytes(keyHex);
			byte[] ivBytes = ByteUtils.hexToBytes(ivHex);
			byte[] encrypted = encryptFromData(plainBytes, keyBytes, ivBytes, isPadding);
			return ByteUtils.bytesToHex(encrypted);
		}
		
		/**
		 * SM4_CBC模式流加密
		 * @param is		输入流
		 * @param os		输出流
		 * @param keyBytes	密钥字节码
		 * @param ivBytes	向量字节码
		 * @throws IOException
		 * @throws InvalidKeyException
		 * @throws InvalidSourceDataException
		 */
		public static void encryptInputStream(InputStream is, OutputStream os, byte[] keyBytes, byte[] ivBytes) throws IOException, InvalidKeyException, InvalidSourceDataException {
			encryptInputStream(is, os, keyBytes, ivBytes, true);
		}
		
		/**
		 * SM4_CBC模式流加密
		 * @param is		输入流
		 * @param os		输出流
		 * @param keyBytes	密钥字节码
		 * @param ivBytes	向量字节码
		 * @param isPadding	是否填充
		 * @throws IOException
		 * @throws InvalidKeyException
		 * @throws InvalidSourceDataException
		 */
		public static void encryptInputStream(InputStream is, OutputStream os, byte[] keyBytes, byte[] ivBytes, boolean isPadding) throws IOException, InvalidKeyException, InvalidSourceDataException {
			byte[] buffer = new byte[1024];
            byte[] data = null;
            byte[] cipherBytes = null;
            int length;
            int point = 0;
            while ((length = is.read(buffer)) != -1) {
            	if(point > 0 && data != null) {
            		cipherBytes = encryptFromData(data, keyBytes, ivBytes, false);
            		os.write(cipherBytes);
            	}
            	data = new byte[length];
            	System.arraycopy(buffer, 0, data, 0, length);
            	point ++;
            }
            cipherBytes = encryptFromData(data, keyBytes, ivBytes, isPadding);
    		os.write(cipherBytes);
    		buffer = null;
    		data = null;
    		cipherBytes = null;
		}
		
		/**
		 * SM4_CBC模式字节码加密
		 * @param plainBytes明文字节码
		 * @param keyBytes	密钥字节码
		 * @param ivBytes	向量字节码
		 * @return 密文字节码
		 * @throws InvalidKeyException 
		 * @throws InvalidSourceDataException 
		 */
		public static byte[] encryptFromData(byte[] plainBytes, byte[] keyBytes, byte[] ivBytes) throws InvalidSourceDataException, InvalidKeyException {
			return encryptFromData(plainBytes, keyBytes, ivBytes, true);
		}
		
		/**
		 * SM4_CBC模式字节码加密
		 * @param plainBytes明文字节码
		 * @param keyBytes	密钥字节码
		 * @param ivBytes	向量字节码
		 * @param isPadding	是否填充
		 * @return 密文字节码
		 * @throws InvalidSourceDataException 
		 * @throws InvalidKeyException 
		 */
		public static byte[] encryptFromData(byte[] plainBytes, byte[] keyBytes, byte[] ivBytes, boolean isPadding) throws InvalidSourceDataException, InvalidKeyException {
			if(plainBytes==null || plainBytes.length == 0) {
				throw new InvalidSourceDataException("[SM4_CBC:encryptFromData]invalid plainBytes");
			}
			if(keyBytes==null || keyBytes.length != 16) {
				throw new InvalidKeyException("[SM4_CBC:encryptFromData]invalid keyBytes");
			}
			if(ivBytes==null || ivBytes.length != 16) {
				throw new InvalidKeyException("[SM4_CBC:encryptFromData]invalid ivBytes");
			}
			try {
				Sm4Context ctx = new Sm4Context();
				ctx.isPadding = isPadding;
				Sm4 sm4 = new Sm4();
				sm4.sm4_setkey_enc(ctx, keyBytes);
				byte[] encrypted = sm4.sm4_crypt_cbc(ctx, ivBytes, plainBytes);
				return encrypted;
			} catch (InvalidContextException e) {
				logger.warning("SM4 CBC Model Encrypt InvalidContextException!");
				return null;
			} catch (InvalidIvException e) {
				logger.warning("SM4 CBC Model Encrypt InvalidIvException!");
				return null;
			} catch (IOException e) {
				logger.warning("SM4 CBC Model Encrypt IOException!");
				return null;
			}
		}

		/**
		 * SM4_CBC模式字符串解密
		 * @param cipherHex	密文十六进制串
		 * @param keyHex	密钥十六进制串
		 * @param ivHex		向量十六进制串
		 * @return 明文字符串
		 * @throws InvalidCryptoDataException 
		 * @throws InvalidKeyException 
		 */
		public static String decryptToText(String cipherHex, String keyHex, String ivHex) throws InvalidCryptoDataException, InvalidKeyException {
			return decryptToText(cipherHex, keyHex, ivHex, true);
		}
		
		/**
		 * SM4_CBC模式字符串解密
		 * @param cipherHex	密文十六进制串
		 * @param keyHex	密钥十六进制串
		 * @param ivHex		向量十六进制串
		 * @param isPadding	是否填充
		 * @return 明文字符串
		 * @throws InvalidCryptoDataException 
		 * @throws InvalidKeyException 
		 */
		public static String decryptToText(String cipherHex, String keyHex, String ivHex, boolean isPadding) throws InvalidCryptoDataException, InvalidKeyException {
			if(StringUtils.length(keyHex)==0 || cipherHex.length() % 32 != 0) {
				throw new InvalidCryptoDataException("[SM4_CBC:decryptToText]invalid cipherHex");
			}
			if(StringUtils.length(keyHex) != 32) {
				throw new InvalidKeyException("[SM4_CBC:decryptToText]invalid keyHex");
			}
			if(StringUtils.length(ivHex) != 32) {
				throw new InvalidKeyException("[SM4_CBC:decryptToText]invalid ivHex");
			}
			byte[] cipherBytes = ByteUtils.hexToBytes(cipherHex);
			byte[] keyBytes = ByteUtils.hexToBytes(keyHex);
			byte[] ivBytes = ByteUtils.hexToBytes(ivHex);
			byte[] decrypted = decryptToData(cipherBytes, keyBytes, ivBytes, isPadding);
			return ByteUtils.bytesToString(decrypted);
		}
		
		/**
		 * SM4_CBC模式十六进制解密
		 * @param cipherHex	密文十六进制串
		 * @param keyHex	密钥十六进制串
		 * @param ivHex		向量十六进制串
		 * @return 明文十六进制串
		 * @throws InvalidCryptoDataException 
		 * @throws InvalidKeyException 
		 */
		public static String decryptToHex(String cipherHex, String keyHex, String ivHex) throws InvalidCryptoDataException, InvalidKeyException {
			return decryptToHex(cipherHex, keyHex, ivHex, true);
		}
		
		/**
		 * SM4_CBC模式十六进制解密
		 * @param cipherHex	密文十六进制串
		 * @param keyHex	密钥十六进制串
		 * @param ivHex		向量十六进制串
		 * @param isPadding	是否填充
		 * @return 明文十六进制串
		 * @throws InvalidCryptoDataException 
		 * @throws InvalidKeyException 
		 */
		public static String decryptToHex(String cipherHex, String keyHex, String ivHex, boolean isPadding) throws InvalidCryptoDataException, InvalidKeyException {
			if(StringUtils.length(keyHex)==0 || cipherHex.length() % 32 != 0) {
				throw new InvalidCryptoDataException("[SM4_CBC:decryptToHex]invalid cipherHex");
			}
			if(StringUtils.length(keyHex) != 32) {
				throw new InvalidKeyException("[SM4_CBC:decryptToHex]invalid keyHex");
			}
			if(StringUtils.length(ivHex) != 32) {
				throw new InvalidKeyException("[SM4_CBC:decryptToHex]invalid ivHex");
			}
			byte[] cipherBytes = ByteUtils.hexToBytes(cipherHex);
			byte[] keyBytes = ByteUtils.hexToBytes(keyHex);
			byte[] ivBytes = ByteUtils.hexToBytes(ivHex);
			byte[] decrypted = decryptToData(cipherBytes, keyBytes, ivBytes, isPadding);
			return ByteUtils.bytesToHex(decrypted);
		}
		
		/**
		 * SM4_CBC模式流解密
		 * @param is		输入流（密文输入）
		 * @param os		输出流（明文输出）
		 * @param keyBytes	密钥字节码
		 * @param ivBytes	向量字节码
		 * @throws IOException
		 * @throws InvalidKeyException
		 * @throws InvalidSourceDataException
		 * @throws InvalidCryptoDataException 
		 */
		public static void decryptInputStream(InputStream is, OutputStream os, byte[] keyBytes, byte[] ivBytes) throws IOException, InvalidKeyException, InvalidCryptoDataException {
			decryptInputStream(is, os, keyBytes, ivBytes, true);
		}
		
		/**
		 * SM4_CBC模式流解密
		 * @param is		输入流（密文输入）
		 * @param os		输出流（明文输出）
		 * @param keyBytes	密钥字节码
		 * @param ivBytes	向量字节码
		 * @param isPadding	是否填充
		 * @throws IOException
		 * @throws InvalidKeyException
		 * @throws InvalidSourceDataException
		 * @throws InvalidCryptoDataException 
		 */
		public static void decryptInputStream(InputStream is, OutputStream os, byte[] keyBytes, byte[] ivBytes, boolean isPadding) throws IOException, InvalidKeyException, InvalidCryptoDataException {
			byte[] buffer = new byte[1024];
            byte[] data = null;
            byte[] plantBytes = null;
            int length;
            int point = 0;
            while ((length = is.read(buffer)) != -1) {
            	if(point > 0 && data != null) {
            		plantBytes = decryptToData(data, keyBytes, ivBytes, false);
            		os.write(plantBytes);
            	}
            	data = new byte[length];
            	System.arraycopy(buffer, 0, data, 0, length);
            	point ++;
            }
            plantBytes = decryptToData(data, keyBytes, ivBytes, isPadding);
    		os.write(plantBytes);
    		buffer = null;
    		data = null;
    		plantBytes = null;
		}
		
		/**
		 * SM4_CBC模式字节码解密
		 * @param cipherBytes	密文字节码
		 * @param keyBytes		密钥字节码
		 * @param ivBytes		向量字节码
		 * @return 明文字符串
		 * @throws InvalidKeyException 
		 * @throws InvalidCryptoDataException 
		 */
		public static byte[] decryptToData(byte[] cipherBytes, byte[] keyBytes, byte[] ivBytes) throws InvalidCryptoDataException, InvalidKeyException {
			return decryptToData(cipherBytes, keyBytes, ivBytes, true);
		}
		
		/**
		 * SM4_CBC模式字节码解密
		 * @param cipherBytes	密文字节码
		 * @param keyBytes		密钥字节码
		 * @param ivBytes		向量字节码
		 * @param isPadding	是否填充
		 * @return 明文字符串
		 * @throws InvalidCryptoDataException 
		 * @throws InvalidKeyException 
		 */
		public static byte[] decryptToData(byte[] cipherBytes, byte[] keyBytes, byte[] ivBytes, boolean isPadding) throws InvalidCryptoDataException, InvalidKeyException {
			if(cipherBytes==null || cipherBytes.length == 0 || cipherBytes.length%16 != 0) {
				throw new InvalidCryptoDataException("[SM4_CBC:decryptToData]invalid plainBytes");
			}
			if(keyBytes==null || keyBytes.length != 16) {
				throw new InvalidKeyException("[SM4_CBC:decryptToData]invalid keyBytes");
			}
			if(ivBytes==null || ivBytes.length != 16) {
				throw new InvalidKeyException("[SM4_CBC:decryptToData]invalid ivBytes");
			}
			try {
				Sm4Context ctx = new Sm4Context();
				ctx.isPadding = isPadding;
				Sm4 sm4 = new Sm4();
				sm4.sm4_setkey_dec(ctx, keyBytes);
				byte[] decrypted = sm4.sm4_crypt_cbc(ctx, ivBytes, cipherBytes);
				return decrypted;
			} catch (InvalidContextException e) {
				logger.warning("SM4 CBC Model Decrypt InvalidContextException!");
				return null;
			} catch (InvalidIvException e) {
				logger.warning("SM4 CBC Model Decrypt InvalidIvException!");
				return null;
			} catch (IOException e) {
				logger.warning("SM4 CBC Model Decrypt IOException!");
				return null;
			}
		}
	}
}
