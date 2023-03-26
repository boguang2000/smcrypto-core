package cn.aotcloud.smcrypto.test.core;

import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import java.util.logging.Logger;

import org.junit.Assert;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

import cn.aotcloud.smcrypto.Sm2Utils;
import cn.aotcloud.smcrypto.exception.InvalidKeyException;
import cn.aotcloud.smcrypto.exception.InvalidSignDataException;
import cn.aotcloud.smcrypto.exception.InvalidSourceDataException;
import cn.aotcloud.smcrypto.util.ByteUtils;
import cn.aotcloud.smcrypto.util.LoggerFactory;

@FixMethodOrder(MethodSorters.DEFAULT)
public class Sm2SignJavaTest {

	private static final Logger logger = LoggerFactory.getLogger(Sm2SignJavaTest.class);

	private final String sourceText = GenerateSm2KeyPair.sourceText;
	private final String sourceHex = ByteUtils.stringToHex(sourceText);
	private final byte[] sourceBytes = ByteUtils.stringToBytes(sourceText);
	
	// 测试密钥对
	private static final String prvKeyHex = GenerateSm2KeyPair.prvKeyHex;
	private static final String pubKeyHex = GenerateSm2KeyPair.pubKeyHex;
	
	private static final byte[] prvKeyBytes = ByteUtils.hexToBytes(prvKeyHex);
	private static final byte[] pubKeyBytes = ByteUtils.hexToBytes(pubKeyHex);
	
	@Test
    public void testText() {
		try {
			Sm2Utils sm2Utils = new Sm2Utils();
			logger.info("----------------Sign & VerifySign(字符串模式)场景描述:采用16进制公私钥对，对字符串形式的明文进行签名验签----------------");
			logger.info("私钥:"+ prvKeyHex);
    		logger.info("公钥:"+ pubKeyHex);
			logger.info("明文:"+ sourceText);
			String signHex = sm2Utils.signFromText(prvKeyHex, sourceText);
			logger.info("签名:" + signHex);
			boolean verify = sm2Utils.verifySignFromText(pubKeyHex, sourceText, signHex);
			logger.info("验签:" + (verify ? "成功" : "失败"));
			//断言为真
			assertTrue(verify);
			logger.info("--------------------------------\n");
		} catch (InvalidSignDataException e) {
			Assert.fail(e.getMessage());
			logger.warning("SM2签名验签InvalidSignDataException异常");
		} catch (InvalidKeyException e) {
			Assert.fail(e.getMessage());
			logger.warning("SM2签名验签InvalidKeyException异常");
		} catch (InvalidSourceDataException e) {
			Assert.fail(e.getMessage());
			logger.warning("SM2签名验签InvalidSourceDataException异常");
		}
    }
	
	@Test
    public void testHex() {
		try {
			Sm2Utils sm2Utils = new Sm2Utils();
			logger.info("----------------Sign & VerifySign(16进制串模式)场景描述:采用16进制公私钥对，对16进制形式的明文进行签名验签----------------");
			logger.info("私钥:"+ prvKeyHex);
    		logger.info("公钥:"+ pubKeyHex);
			logger.info("明文:"+ sourceHex);
			String signHex = sm2Utils.signFromHex(prvKeyHex, sourceHex);
			logger.info("签名:" + signHex);
			boolean verify = sm2Utils.verifySignFromHex(pubKeyHex, sourceHex, signHex);
			logger.info("验签:" + (verify ? "成功" : "失败"));
			//断言为真
			assertTrue(verify);
			logger.info("--------------------------------\n");
		} catch (InvalidSignDataException e) {
			Assert.fail(e.getMessage());
			logger.warning("SM2签名验签InvalidSignDataException异常");
		} catch (InvalidKeyException e) {
			Assert.fail(e.getMessage());
			logger.warning("SM2签名验签InvalidKeyException异常");
		} catch (InvalidSourceDataException e) {
			Assert.fail(e.getMessage());
			logger.warning("SM2签名验签InvalidSourceDataException异常");
		}
    }
	
	@Test
    public void testData() {
		try {
			Sm2Utils sm2Utils = new Sm2Utils();
			logger.info("----------------Sign & VerifySign(字节码模式)场景描述:采用16进制公私钥对，对字节码形式的明文进行签名验签----------------");
			logger.info("私钥:"+ Arrays.toString(prvKeyBytes));
    		logger.info("公钥:"+ Arrays.toString(pubKeyBytes));
			logger.info("明文:"+ Arrays.toString(sourceBytes));
			byte[] signData = sm2Utils.signFromData(prvKeyBytes, sourceBytes);
			logger.info("签名:" + Arrays.toString(signData));
			boolean verify = sm2Utils.verifySignFromData(pubKeyBytes, sourceBytes, signData);
			logger.info("验签:" + (verify ? "成功" : "失败"));
			//断言为真
			assertTrue(verify);
			logger.info("--------------------------------\n");
		} catch (InvalidSignDataException e) {
			Assert.fail(e.getMessage());
			logger.warning("SM2签名验签InvalidSignDataException异常");
		} catch (InvalidKeyException e) {
			Assert.fail(e.getMessage());
			logger.warning("SM2签名验签InvalidKeyException异常");
		} catch (InvalidSourceDataException e) {
			Assert.fail(e.getMessage());
			logger.warning("SM2签名验签InvalidSourceDataException异常");
		}
    }
}
