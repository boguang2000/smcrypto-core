package cn.aotcloud.smcrypto.test.core;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import java.util.logging.Logger;

import org.junit.Assert;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

import cn.aotcloud.smcrypto.Sm4Utils;
import cn.aotcloud.smcrypto.exception.InvalidCryptoDataException;
import cn.aotcloud.smcrypto.exception.InvalidKeyException;
import cn.aotcloud.smcrypto.exception.InvalidSourceDataException;
import cn.aotcloud.smcrypto.util.ByteUtils;
import cn.aotcloud.smcrypto.util.LoggerFactory;
import cn.aotcloud.smcrypto.util.StringUtils;

@FixMethodOrder(MethodSorters.DEFAULT)
public class Sm4EcbEncryptJavaTest {

	private static final Logger logger = LoggerFactory.getLogger(Sm4EcbEncryptJavaTest.class);

	private final String sourceText = GenerateSm2KeyPair.sourceText;
	private final String sourceHex = ByteUtils.stringToHex(GenerateSm2KeyPair.sourceText);
	private final byte[] sourceBytes = ByteUtils.stringToBytes(GenerateSm2KeyPair.sourceText);

	private final String keyHex = GenerateSm2KeyPair.keyHex;
	private final byte[] keyBytes = ByteUtils.hexToBytes(keyHex);
	
	@Test
    public void testText_ECB() {
		try {
			logger.info("----------------SM4_ECB(字符串模式)场景描述:采用字符串密码，对字符串形式的明文进行加密解密----------------");
			logger.info("明文:" + sourceText);
			logger.info("密码:" + keyHex);
			String sm4EncHex = Sm4Utils.ECB.encryptFromText(sourceText, keyHex);
			String sm4DecStr = Sm4Utils.ECB.decryptToText(sm4EncHex, keyHex);
			logger.info("加密:" + sm4EncHex);
			logger.info("解密:" + sm4DecStr);
			logger.info("验证:" + (StringUtils.equals(sourceText, sm4DecStr) ? "成功" : "失败"));
			//断言相等
			assertEquals(sourceText, sm4DecStr);
			logger.info("--------------------------------\n");
		} catch (InvalidSourceDataException e) {
			Assert.fail(e.getMessage());
			logger.warning("SM4_ECB加密解密InvalidSourceDataException异常");
		} catch (InvalidKeyException e) {
			Assert.fail(e.getMessage());
			logger.warning("SM4_ECB加密解密InvalidKeyException异常");
		} catch (InvalidCryptoDataException e) {
			Assert.fail(e.getMessage());
			logger.warning("SM4_ECB加密解密InvalidCryptoDataException异常");
		}
	}
	
	@Test
    public void testHex_ECB() {
		try {
			logger.info("----------------SM4_ECB(16进制串模式)场景描述:采用16进制串密码，对16进制形式的明文进行加密解密----------------");
			logger.info("明文:" + sourceHex);
			logger.info("密码:" + keyHex);
			String sm4EncHex = Sm4Utils.ECB.encryptFromHex(sourceHex, keyHex);
			String sm4DecHex = Sm4Utils.ECB.decryptToHex(sm4EncHex, keyHex);
			logger.info("加密:" + sm4EncHex);
			logger.info("解密:" + sm4DecHex);
			logger.info("验证:" + (StringUtils.equals(sourceHex, sm4DecHex) ? "成功" : "失败"));
			//断言相等
			assertEquals(sourceHex, sm4DecHex);
			logger.info("--------------------------------\n");
		} catch (InvalidSourceDataException e) {
			Assert.fail(e.getMessage());
			logger.warning("SM4_ECB加密解密InvalidSourceDataException异常");
		} catch (InvalidKeyException e) {
			Assert.fail(e.getMessage());
			logger.warning("SM4_ECB加密解密InvalidKeyException异常");
		} catch (InvalidCryptoDataException e) {
			Assert.fail(e.getMessage());
			logger.warning("SM4_ECB加密解密InvalidCryptoDataException异常");
		}
	}
	
	@Test
    public void testData_ECB() {
		try {
			logger.info("----------------SM4_ECB(字节码模式)场景描述:采用字节码密码，对字节码形式的明文进行加密解密----------------");
			logger.info("明文:" + Arrays.toString(sourceBytes));
			logger.info("密码:" + Arrays.toString(keyBytes));
			byte[] sm4EncBytes = Sm4Utils.ECB.encryptFromData(sourceBytes, keyBytes);
			byte[] sm4DecBytes = Sm4Utils.ECB.decryptToData(sm4EncBytes, keyBytes);
			logger.info("加密:" + Arrays.toString(sm4EncBytes));
			logger.info("解密:" + Arrays.toString(sm4DecBytes));
			logger.info("验证:" + (Arrays.equals(sourceBytes, sm4DecBytes) ? "成功" : "失败"));
			//断言为真
			assertTrue(Arrays.equals(sourceBytes, sm4DecBytes));
			logger.info("--------------------------------\n");
		} catch (InvalidSourceDataException e) {
			Assert.fail(e.getMessage());
			logger.warning("SM4_ECB加密解密InvalidSourceDataException异常");
		} catch (InvalidKeyException e) {
			Assert.fail(e.getMessage());
			logger.warning("SM4_ECB加密解密InvalidKeyException异常");
		} catch (InvalidCryptoDataException e) {
			Assert.fail(e.getMessage());
			logger.warning("SM4_ECB加密解密InvalidCryptoDataException异常");
		}
	}
}
