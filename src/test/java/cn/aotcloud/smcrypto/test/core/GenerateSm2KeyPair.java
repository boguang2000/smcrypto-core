package cn.aotcloud.smcrypto.test.core;

import static org.junit.Assert.assertEquals;

import java.util.logging.Logger;

import org.junit.Test;

import cn.aotcloud.smcrypto.Sm2Utils;
import cn.aotcloud.smcrypto.util.LoggerFactory;

public class GenerateSm2KeyPair {
	
	private static final Logger logger = LoggerFactory.getLogger(GenerateSm2KeyPair.class);
	
	private static final Sm2Utils sm2Utils = new Sm2Utils();
	
	private static final String[] keyPair = sm2Utils.generateKeyPair();
	
	public static final String prvKeyHex = keyPair[0]; //"2414646A51177B2D93F9A46637744E0E6610432F4B2E6F36A181B7A397814A0C";
	public static final String pubKeyHex = keyPair[1]; //"04F81D5B46C5293B29F9B77FF2F28A7C9BFC33ACD3A72FAAA8E18FBA8E9D91E9A59E82D3C126AED4F65A24990F46E91FE933BD21F1B575783408A2E3A103E7BF7D";
	
	public static final String keyHex = "0A01D5547DB54B77BB983F2900DACA98";
	public static final String ivHex = "616F737461722E73676974672E636F6D";
	
	public static final String sourceText = "密码工作机构发现核心密码、普通密码泄密或者影响核心密码、普通密码安全的重大问题、风险隐患的，应当立即采取应对措施，并及时向保密行政管理部门、密码管理部门报告，由保密行政管理部门、密码管理部门会同有关部门组织开展调查、处置，并指导有关密码工作机构及时消除安全隐患。";

	@Test
    public void testGenerateKey() {
		logger.info("----------------SM2 公私钥生成----------------");
		Sm2Utils sm2Utils = new Sm2Utils();
		String[] keyPair = sm2Utils.generateKeyPair();
		String prvKeyHex = keyPair[0];
		String pubKeyHex = keyPair[1];
		logger.info("生成私钥:"+ prvKeyHex);
		logger.info("生成公钥:"+ pubKeyHex);
		String pubKeyHex_ = sm2Utils.getPublicKey(prvKeyHex);
		logger.info("计算公钥:"+ pubKeyHex_);
		//断言相等
		assertEquals(pubKeyHex, pubKeyHex_);
		logger.info("--------------------------------\n");
	}
}
