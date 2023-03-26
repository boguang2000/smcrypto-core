package cn.aotcloud.smcrypto.test.core;

import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import java.util.logging.Logger;

import org.junit.Assert;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

import cn.aotcloud.smcrypto.Sm3Utils;
import cn.aotcloud.smcrypto.exception.InvalidSourceDataException;
import cn.aotcloud.smcrypto.util.ByteUtils;
import cn.aotcloud.smcrypto.util.LoggerFactory;

@FixMethodOrder(MethodSorters.DEFAULT)
public class Sm3EncryptJavaTest {

	private static final Logger logger = LoggerFactory.getLogger(Sm3EncryptJavaTest.class);

	private final String sourceText = GenerateSm2KeyPair.sourceText;
	private final String sourceHex = ByteUtils.stringToHex(sourceText);
	private final byte[] sourceBytes = ByteUtils.stringToBytes(sourceText);
	
	@Test
	public void testText() {
		try {
			logger.info("----------------SM3(字符串模式)场景描述:对字符串形式的明文进行SM3摘要计算----------------");
			logger.info("明文:"+ sourceText);
			String sm3EncHex = Sm3Utils.encryptFromText(sourceText);
			logger.info("摘要:" + sm3EncHex);
			//断言为真
			assertTrue(sm3EncHex!=null && sm3EncHex.length()==64);
			logger.info("--------------------------------\n");
		} catch (InvalidSourceDataException e) {
			Assert.fail(e.getMessage());
			logger.warning("SM3摘要InvalidSourceDataException异常");
		}
	}
	
	@Test
	public void testHex() {
		try {
			logger.info("----------------SM3(16进制串模式)场景描述:对16进制串形式的明文进行SM3摘要计算----------------");
			logger.info("明文:"+ sourceHex);
			String sm3EncHex = Sm3Utils.encryptFromHex(sourceHex);
			logger.info("摘要:" + sm3EncHex);
			//断言为真
			assertTrue(sm3EncHex!=null && sm3EncHex.length()==64);
			logger.info("--------------------------------\n");
		} catch (InvalidSourceDataException e) {
			Assert.fail(e.getMessage());
			logger.warning("SM3摘要InvalidSourceDataException异常");
		}
	}
	
	@Test
	public void testData() {
		try {
			logger.info("----------------SM3(字节码模式)场景描述:对字节码形式的明文进行SM3摘要计算----------------");
			logger.info("明文:"+ Arrays.toString(sourceBytes));
			byte[] sm3EncBytes = Sm3Utils.encryptFromData(sourceBytes);
			logger.info("摘要:" + Arrays.toString(sm3EncBytes));
			//断言为真
			assertTrue(sm3EncBytes!=null && sm3EncBytes.length == 32);
			logger.info("--------------------------------\n");
		} catch (InvalidSourceDataException e) {
			Assert.fail(e.getMessage());
			logger.warning("SM3摘要InvalidSourceDataException异常");
		}
	}
}
