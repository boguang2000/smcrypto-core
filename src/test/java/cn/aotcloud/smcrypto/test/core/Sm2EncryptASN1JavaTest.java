package cn.aotcloud.smcrypto.test.core;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import java.util.logging.Logger;

import org.junit.Assert;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

import cn.aotcloud.smcrypto.Sm2Utils;
import cn.aotcloud.smcrypto.exception.InvalidCryptoDataException;
import cn.aotcloud.smcrypto.exception.InvalidKeyException;
import cn.aotcloud.smcrypto.exception.InvalidSourceDataException;
import cn.aotcloud.smcrypto.util.ByteUtils;
import cn.aotcloud.smcrypto.util.LoggerFactory;
import cn.aotcloud.smcrypto.util.StringUtils;

@FixMethodOrder(MethodSorters.DEFAULT)
public class Sm2EncryptASN1JavaTest {
	
	private static final Logger logger = LoggerFactory.getLogger(Sm2EncryptASN1JavaTest.class);
	
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
			logger.info("----------------SM2(ASN1字符串模式)场景描述:采用16进制公私钥对，对字符串形式的明文进行加密解密（ANS1密文对象转换方式）----------------");
			logger.info("注意:SM2 ASN1编码模式只支持C1C3C2密文格式");
    		logger.info("私钥:"+ prvKeyHex);
    		logger.info("公钥:"+ pubKeyHex);
    		logger.info("明文:"+ sourceText);
			Sm2Utils sm2Utils = new Sm2Utils();
    		String cipherHex = sm2Utils.encryptASN1FromText(pubKeyHex, sourceText);
			logger.info("C1C3C2加密:"+ cipherHex);
			String plantText = sm2Utils.decryptASN1ToText(prvKeyHex, cipherHex);
			logger.info("C1C3C2解密:"+ plantText);
			logger.info("C1C3C2比较:" + (StringUtils.equals(sourceText, plantText) ? "成功" : "失败"));
			//断言相等
			assertEquals(sourceText, plantText);
			logger.info("--------------------------------\n");
		} catch (InvalidCryptoDataException e) {
			Assert.fail(e.getMessage());
			logger.warning("SM2加密解密InvalidCryptoDataException异常");
		} catch (InvalidKeyException e) {
			Assert.fail(e.getMessage());
			logger.warning("SM2加密解密InvalidKeyException异常");
		} catch (InvalidSourceDataException e) {
			Assert.fail(e.getMessage());
			logger.warning("SM2加密解密InvalidSourceDataException异常");
		}
	}
	
	@Test
    public void testHex() {
    	try {
			logger.info("----------------SM2(ASN116进制串模式)场景描述:采用16进制公私钥对，对16进制串形式的明文进行加密解密（ANS1密文对象转换方式）----------------");
			logger.info("注意:SM2 ASN1编码模式只支持C1C3C2密文格式");
    		logger.info("私钥:"+ prvKeyHex);
    		logger.info("公钥:"+ pubKeyHex);
    		logger.info("明文:"+ sourceHex);
			Sm2Utils sm2Utils = new Sm2Utils();
    		String cipherHex = sm2Utils.encryptASN1FromHex(pubKeyHex, sourceHex);
			logger.info("C1C3C2加密:"+ cipherHex);
			String plantHex  = sm2Utils.decryptASN1ToHex(prvKeyHex, cipherHex);
			logger.info("C1C3C2解密:"+ plantHex);
			logger.info("C1C3C2比较:" + (StringUtils.equals(sourceHex, plantHex) ? "成功" : "失败"));
			//断言相等
			assertEquals(sourceHex, plantHex);
			logger.info("--------------------------------\n");
		} catch (InvalidCryptoDataException e) {
			Assert.fail(e.getMessage());
			logger.warning("SM2加密解密InvalidCryptoDataException异常");
		} catch (InvalidKeyException e) {
			Assert.fail(e.getMessage());
			logger.warning("SM2加密解密InvalidKeyException异常");
		} catch (InvalidSourceDataException e) {
			Assert.fail(e.getMessage());
			logger.warning("SM2加密解密InvalidSourceDataException异常");
		}
	}
	
	@Test
    public void testData() {
    	try {
			logger.info("----------------SM2(ASN1字节码模式)场景描述:采用字节码公私钥对，对字节码形式的明文进行加密解密（ANS1密文对象转换方式）----------------");
			logger.info("注意:SM2 ASN1编码模式只支持C1C3C2密文格式");
    		logger.info("私钥:"+ Arrays.toString(prvKeyBytes));
    		logger.info("公钥:"+ Arrays.toString(pubKeyBytes));
    		logger.info("明文:"+ Arrays.toString(sourceBytes));
			Sm2Utils sm2Utils = new Sm2Utils();
    		byte[] cipherData = sm2Utils.encryptASN1FromData(pubKeyBytes, sourceBytes);
			logger.info("C1C3C2加密:"+ Arrays.toString(cipherData));
			byte[] plantData  = sm2Utils.decryptASN1ToData(prvKeyBytes, cipherData);
			logger.info("C1C3C2解密:"+ Arrays.toString(plantData));
			logger.info("C1C3C2比较:" + (Arrays.equals(sourceBytes, plantData) ? "成功" : "失败"));
			//断言为真
			assertTrue(Arrays.equals(sourceBytes, plantData));
			logger.info("--------------------------------\n");
		} catch (InvalidCryptoDataException e) {
			Assert.fail(e.getMessage());
			logger.warning("SM2加密解密InvalidCryptoDataException异常");
		} catch (InvalidKeyException e) {
			Assert.fail(e.getMessage());
			logger.warning("SM2加密解密InvalidKeyException异常");
		} catch (InvalidSourceDataException e) {
			Assert.fail(e.getMessage());
			logger.warning("SM2加密解密InvalidSourceDataException异常");
		}
	}
}
