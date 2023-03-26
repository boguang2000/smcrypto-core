package cn.aotcloud.smcrypto;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;

import cn.aotcloud.smcrypto.exception.InvalidCryptoDataException;
import cn.aotcloud.smcrypto.exception.InvalidCryptoParamsException;
import cn.aotcloud.smcrypto.exception.InvalidKeyException;
import cn.aotcloud.smcrypto.exception.InvalidSignDataException;
import cn.aotcloud.smcrypto.util.ByteUtils;
import cn.aotcloud.smcrypto.util.CommonUtils;
import cn.aotcloud.smcrypto.util.IOUtils;

/**
 * SM2加密器
 * 注意:由于对象内存在buffer, 请勿多线程同时操作一个实例, 每次new一个Cipher使用,或使用ThreadLocal保持每个线程一个Cipher实例.
 * 
 */
public class Sm2Cipher {

	/**
	 * SM2的ECC椭圆曲线参数
	 */
	private static final BigInteger SM2_ECC_P = new BigInteger("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", 16);
	private static final BigInteger SM2_ECC_A = new BigInteger("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC", 16);
	private static final BigInteger SM2_ECC_B = new BigInteger("28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93", 16);
	private static final BigInteger SM2_ECC_N = new BigInteger("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123", 16);
	private static final BigInteger SM2_ECC_GX = new BigInteger("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7", 16);
	private static final BigInteger SM2_ECC_GY = new BigInteger("BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0", 16);

	private static final byte[] DEFAULT_USER_ID = "1234567812345678".getBytes();

	private ECCurve curve;// ECC曲线
	private ECPoint pointG;// 基点
	private ECKeyPairGenerator keyPairGenerator;// 密钥对生成器
	private CipherMode cipherMode;// 密文格式

	private ECPoint alternateKeyPoint;
	private Sm3Digest alternateKeyDigest;
	private Sm3Digest c3Digest;
	private int alternateKeyCount;
	private byte alternateKey[];
	private byte alternateKeyOff;
	
	private String randomKeyHex;

	public Sm2Cipher() {
		this(CipherMode.C1C2C3);
	}
	
	/**
	 * 默认椭圆曲线参数的SM2加密器
	 * 
	 * @param cipherMode	密文格式
	 */
	public Sm2Cipher(CipherMode cipherMode) {
		this(new SecureRandom(), cipherMode);
	}
	
	/**
	 * 默认椭圆曲线参数的SM2加密器
	 * 
	 * @param cipherMode	密文格式
	 * @param randomKeyHex	指定16进制随机数
	 */
	public Sm2Cipher(CipherMode cipherMode, String randomKeyHex) {
		this(new SecureRandom(), cipherMode);
		this.randomKeyHex = randomKeyHex;
	}

	/**
	 * 默认椭圆曲线参数的SM2加密器
	 * 
	 * @param secureRandom	秘钥生成随机数
	 * @param type	密文格式
	 */
	private Sm2Cipher(SecureRandom secureRandom, CipherMode cipherMode) {
		this(secureRandom, cipherMode, SM2_ECC_P, SM2_ECC_A, SM2_ECC_B, SM2_ECC_N, SM2_ECC_GX, SM2_ECC_GY);
	}

	/**
	 * 默认椭圆曲线参数的SM2加密器
	 * 
	 * @param secureRandom	秘钥生成随机数
	 * @param type	密文格式
	 * @param eccP	p
	 * @param eccA	a
	 * @param eccB	b
	 * @param eccN	n
	 * @param eccGx	gx
	 * @param eccGy	gy
	 */
	@SuppressWarnings({ "unused", "deprecation" })
	private Sm2Cipher(SecureRandom secureRandom, CipherMode cipherMode, BigInteger eccP, BigInteger eccA, BigInteger eccB, BigInteger eccN, BigInteger eccGx, BigInteger eccGy) {
		//if (type == null) {
		//	throw new InvalidCryptoParamsException("[SM2]type of the SM2Cipher is null");
		//}
		if (eccP == null || eccA == null || eccB == null || eccN == null || eccGx == null || eccGy == null) {
			throw new InvalidCryptoParamsException("[SM2]ecc params of the SM2Cipher is null");
		}
		if (secureRandom == null) {
			secureRandom = new SecureRandom();
		}
		this.cipherMode = cipherMode;

		// 曲线
		ECFieldElement gxFieldElement = new ECFieldElement.Fp(eccP, eccGx);
		ECFieldElement gyFieldElement = new ECFieldElement.Fp(eccP, eccGy);
		this.curve = new ECCurve.Fp(eccP, eccA, eccB);

		// 密钥对生成器
		this.pointG = curve.createPoint(SM2_ECC_GX, SM2_ECC_GY);
		ECDomainParameters domainParams = new ECDomainParameters(curve, pointG, eccN);
		ECKeyGenerationParameters keyGenerationParams = new ECKeyGenerationParameters(domainParams, secureRandom);
		this.keyPairGenerator = new ECKeyPairGenerator();
		this.keyPairGenerator.init(keyGenerationParams);
	}

	private final void resetKey() {
		this.alternateKeyDigest = new Sm3Digest();
		this.c3Digest = new Sm3Digest();
		byte x[] = CommonUtils.byteConvert32Bytes(alternateKeyPoint.normalize().getXCoord().toBigInteger());
		byte y[] = CommonUtils.byteConvert32Bytes(alternateKeyPoint.normalize().getYCoord().toBigInteger());
		this.c3Digest.update(x, 0, x.length);

		this.alternateKeyDigest.update(x);
		this.alternateKeyDigest.update(y);
		this.alternateKeyCount = 1;
		nextKey();
	}

	private final void nextKey() {

		Sm3Digest digest = new Sm3Digest(this.alternateKeyDigest);
		digest.update((byte) (alternateKeyCount >> 24 & 0xff));
		digest.update((byte) (alternateKeyCount >> 16 & 0xff));
		digest.update((byte) (alternateKeyCount >> 8 & 0xff));
		digest.update((byte) (alternateKeyCount & 0xff));
		alternateKey = digest.doFinal();

		this.alternateKeyOff = 0;
		this.alternateKeyCount++;
	}

	private final byte[] getZ(byte[] userId, ECPoint userKey) {
		Sm3Digest digest = new Sm3Digest();
		if (userId == null) {
			userId = DEFAULT_USER_ID;
		}

		int len = userId.length * 8;
		digest.update((byte) (len >> 8 & 0xFF));
		digest.update((byte) (len & 0xFF));
		digest.update(userId);

		byte[] p = CommonUtils.byteConvert32Bytes(SM2_ECC_A);
		digest.update(p);
		p = CommonUtils.byteConvert32Bytes(SM2_ECC_B);
		digest.update(p);
		p = CommonUtils.byteConvert32Bytes(SM2_ECC_GX);
		digest.update(p);
		p = CommonUtils.byteConvert32Bytes(SM2_ECC_GY);
		digest.update(p);
		p = CommonUtils.byteConvert32Bytes(userKey.normalize().getXCoord().toBigInteger());
		digest.update(p);
		p = CommonUtils.byteConvert32Bytes(userKey.normalize().getYCoord().toBigInteger());
		digest.update(p);

		return digest.doFinal();
	}
	
	/**
	 * @return 产生SM2公私钥对(随机)
	 */
	public final Sm2KeyPair generateKeyPair() {
		AsymmetricCipherKeyPair keyPair = keyPairGenerator.generateKeyPair();
		ECPrivateKeyParameters privateKeyParams = (ECPrivateKeyParameters) keyPair.getPrivate();
		ECPublicKeyParameters publicKeyParams = (ECPublicKeyParameters) keyPair.getPublic();
		BigInteger privateKey = privateKeyParams.getD();
		ECPoint publicKey = publicKeyParams.getQ();
		return new Sm2KeyPair(privateKey.toByteArray(), publicKey.getEncoded(false));
	}
	
	public byte[] getPublicKey(byte[] privateKey) {
		ECDomainParameters domainParams = new ECDomainParameters(curve, pointG, SM2_ECC_N);
		BigInteger d = new BigInteger(privateKey);
		ECPoint Q = domainParams.getG().multiply(d);
		return Q.getEncoded(false);
	}

	/**
	 * SM2加密, ASN.1编码
	 * @param pubKeyBytes	公钥
	 * @param dataBytes		数据
	 * @throws InvalidKeyException 
	 * @throws InvalidCryptoDataException 
	 */
	public final byte[] encrypt(byte[] pubKeyBytes, byte[] dataBytes) throws InvalidKeyException {
		Sm2EncryptedData encryptedData = encryptInner(pubKeyBytes, dataBytes);
		if (encryptedData == null) {
			return null;
		}
		ECPoint c1 = encryptedData.getC1();
		byte[] c2 = encryptedData.getC2();
		byte[] c3 = encryptedData.getC3();
		// C1 C2 C3拼装成加密字串
		String encHex = null;
		switch (this.cipherMode) {
		case C1C2C3:
			encHex = ByteUtils.bytesToHex(c1.getEncoded(false)) + ByteUtils.bytesToHex(c2) + ByteUtils.bytesToHex(c3);
			break;
		case C1C3C2:
			encHex = ByteUtils.bytesToHex(c1.getEncoded(false)) + ByteUtils.bytesToHex(c3) + ByteUtils.bytesToHex(c2);
			break;
		default:
			throw new InvalidCryptoParamsException("[SM2:Encrypt]invalid type(" + String.valueOf(this.cipherMode) + ")");
		}
		return ByteUtils.hexToBytes(encHex);
	}

	/**
	 * SM2加密, ASN.1编码
	 * @param pubKeyBytes	公钥
	 * @param data	数据
	 * @throws InvalidKeyException 
	 */
	public final byte[] encryptToASN1(byte[] pubKeyBytes, byte[] data) throws InvalidKeyException {
		Sm2EncryptedData encryptedData = encryptInner(pubKeyBytes, data);
		if (encryptedData == null) {
			return null;
		}
		ECPoint c1 = encryptedData.getC1();
		byte[] c2 = encryptedData.getC2();
		byte[] c3 = encryptedData.getC3();

		ASN1Integer x = new ASN1Integer(c1.normalize().getXCoord().toBigInteger());
		ASN1Integer y = new ASN1Integer(c1.normalize().getYCoord().toBigInteger());
		DEROctetString derC2 = new DEROctetString(c2);
		DEROctetString derC3 = new DEROctetString(c3);
		ASN1EncodableVector vector = new ASN1EncodableVector();
		vector.add(x);
		vector.add(y);
		switch (this.cipherMode) {
		case C1C2C3:
			vector.add(derC2);
			vector.add(derC3);
			break;
		case C1C3C2:
			vector.add(derC3);
			vector.add(derC2);
			break;
		default:
			throw new InvalidCryptoParamsException("[SM2:EncryptASN1]invalid type(" + String.valueOf(this.cipherMode) + ")");
		}
		
		DERSequence seq = new DERSequence(vector);
		try {
			return seq.getEncoded(ASN1Encoding.DER);
		} catch (IOException e) {
			throw new InvalidKeyException("Invalid DEROutputStream");
		}
	}

	protected final Sm2EncryptedData encryptInner(byte[] pubKeyBytes, byte[] data) throws InvalidKeyException {
		if (pubKeyBytes == null || pubKeyBytes.length == 0) {
			throw new InvalidCryptoParamsException("[SM2:Encrypt]key is null");
		}
		if (data == null || data.length == 0) {
			return null;
		}

		// C2位数据域
		byte[] c2 = new byte[data.length];
		System.arraycopy(data, 0, c2, 0, data.length);

		ECPoint keyPoint;
		try {
			keyPoint = curve.decodePoint(pubKeyBytes);
		} catch (Exception e) {
			throw new InvalidKeyException("[SM2:Encrypt]invalid key data(format)", e);
		}
		AsymmetricCipherKeyPair generatedKey = (this.randomKeyHex == null ?  keyPairGenerator.generateKeyPair() : this.generateKeyPair(this.randomKeyHex));
		//AsymmetricCipherKeyPair generatedKey = keyPairGenerator.generateKeyPair();
		ECPrivateKeyParameters privateKeyParams = (ECPrivateKeyParameters) generatedKey.getPrivate();
		ECPublicKeyParameters publicKeyParams = (ECPublicKeyParameters) generatedKey.getPublic();
		BigInteger privateKey = privateKeyParams.getD();
		ECPoint c1 = publicKeyParams.getQ();
		this.alternateKeyPoint = keyPoint.multiply(privateKey);
		resetKey();

		this.c3Digest.update(c2);
		for (int i = 0; i < c2.length; i++) {
			if (alternateKeyOff >= alternateKey.length) {
				nextKey();
			}
			c2[i] ^= alternateKey[alternateKeyOff++];
		}
		byte p[] = CommonUtils.byteConvert32Bytes(alternateKeyPoint.normalize().getYCoord().toBigInteger());
		this.c3Digest.update(p);
		byte[] c3 = this.c3Digest.doFinal();
		resetKey();

		return new Sm2EncryptedData(c1, c2, c3);
	}

	@Deprecated
	protected AsymmetricCipherKeyPair generateKeyPair(String randomKeyHex) {
		ECDomainParameters domainParams = new ECDomainParameters(curve, pointG, SM2_ECC_N);
		BigInteger n = domainParams.getN();
		BigInteger d = new BigInteger(randomKeyHex, 16);
		if(d.equals(BigInteger.valueOf(0)) || (d.compareTo(n) >= 0)) {
			throw new InvalidCryptoParamsException("[SM2:generateKeyPair]invalid randomKeyData, random D mast be greater than Param N");
		}
		ECPoint Q = domainParams.getG().multiply(d);
		return new AsymmetricCipherKeyPair(new ECPublicKeyParameters(Q, domainParams), new ECPrivateKeyParameters(d, domainParams));
	}
	
	/**
	 * SM2解密
	 * @param prvKeyBytes	私钥
	 * @param dataBytes		数据
	 * @throws InvalidCryptoDataException 
	 * @throws InvalidKeyException 
	 * @throws UnsupportedEncodingException
	 */
	public final byte[] decrypt(byte[] prvKeyBytes, byte[] dataBytes) throws InvalidKeyException, InvalidCryptoDataException {
		if (prvKeyBytes == null || prvKeyBytes.length == 0) {
			return null;
		}

		if (dataBytes == null || dataBytes.length == 0) {
			return null;
		}
		// 加密字节数组转换为十六进制的字符串 长度变为encryptedData.length * 2
		String data = ByteUtils.bytesToHex(dataBytes);
		int datLength = data.length();
		byte[] c1Bytes = ByteUtils.hexToBytes(data.substring(0, 130));
		int c2Len = 0;
		byte[] c2 = null;
		byte[] c3 = null;
		switch (this.cipherMode) {
		case C1C2C3:
			/**
			 * 分解加密字串 （C1 = C1标志位2位 + C1实体部分128位 = 130） （C2 = encryptedData.length * 2 - C1长度 - C2长度） （C3 = C3实体部分64位 = 64） 
			 */
			c2Len = dataBytes.length - 97;
			c2 = ByteUtils.hexToBytes(data.substring(130, 130 + 2 * c2Len));
			c3 = ByteUtils.hexToBytes(data.substring(130 + 2 * c2Len, 194 + 2 * c2Len));

			return decryptInner(prvKeyBytes, c1Bytes, c2, c3);
		case C1C3C2:
			/**
			 * 分解加密字串 （C1 = C1标志位2位 + C1实体部分128位 = 130） （C3 = C3实体部分64位 = 64） （C2 = encryptedData.length * 2 - C1长度 - C2长度）
			 */
			c3 = ByteUtils.hexToBytes(data.substring(130, 130 + 64));
			c2 = ByteUtils.hexToBytes(data.substring(130 + 64, datLength));

			return decryptInner(prvKeyBytes, c1Bytes, c2, c3);
		default:
			throw new InvalidCryptoParamsException("[SM2:Encrypt]invalid type(" + String.valueOf(this.cipherMode) + ")");
		}
		
	}

	/**
	 * SM2解密, ASN.1编码
	 * @param prvKeyBytes	私钥
	 * @param data			数据
	 */
	public final byte[] decryptFromASN1(byte[] prvKeyBytes, byte[] data) throws InvalidKeyException, InvalidCryptoDataException {
		if (data == null || data.length == 0) {
			return null;
		}

		ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(data);
		ASN1InputStream asn1InputStream = new ASN1InputStream(byteArrayInputStream);
		ASN1Object derObj;
		ASN1Object endObj;
		try {
			derObj = asn1InputStream.readObject();
			endObj = asn1InputStream.readObject();
			if(endObj != null) {
				throw new InvalidCryptoDataException("[SM2:decrypt:ASN1]invalid encrypted data");
			}
		} catch (IOException e) {
			throw new InvalidCryptoDataException("[SM2:decrypt:ASN1]invalid encrypted data", e);
		} finally {
			IOUtils.closeQuietly(byteArrayInputStream);
			IOUtils.closeQuietly(asn1InputStream);
		}
		ASN1Sequence asn1 = (ASN1Sequence) derObj;
		ASN1Integer x = (ASN1Integer) asn1.getObjectAt(0);
		ASN1Integer y = (ASN1Integer) asn1.getObjectAt(1);
		ECPoint c1;
		try {
			c1 = curve.createPoint(x.getValue(), y.getValue());
		} catch (Exception e) {
			throw new InvalidCryptoDataException("[SM2:decrypt:ASN1]invalid encrypted data, c1", e);
		}
		byte[] c2;
		byte[] c3;
		switch (this.cipherMode) {
		case C1C2C3:
			c2 = ((DEROctetString) asn1.getObjectAt(2)).getOctets();
			c3 = ((DEROctetString) asn1.getObjectAt(3)).getOctets();
			break;
		case C1C3C2:
			c3 = ((DEROctetString) asn1.getObjectAt(2)).getOctets();
			c2 = ((DEROctetString) asn1.getObjectAt(3)).getOctets();
			break;
		default:
			throw new InvalidCryptoParamsException("[SM2:Decrypt:ASN1]invalid type(" + String.valueOf(this.cipherMode) + ")");
		}

		return decryptInner(prvKeyBytes, c1.getEncoded(false), c2, c3);
	}

	private final byte[] decryptInner(byte[] prvKeyBytes, byte[] c1, byte[] c2, byte[] c3) throws InvalidKeyException, InvalidCryptoDataException {
		if (prvKeyBytes == null || prvKeyBytes.length == 0) {
			throw new InvalidCryptoParamsException("[SM2:Decrypt]key is null");
		}
		if (c1 == null || c1.length <= 0 || c2 == null || c2.length <= 0 || c3 == null || c3.length <= 0) {
			throw new InvalidCryptoDataException("[SM2:Decrypt]invalid encrypt data, c1 / c2 / c3 is null or empty");
		}

		BigInteger decryptKey = new BigInteger(1, prvKeyBytes);
		ECPoint c1Point;
		try {
			c1Point = curve.decodePoint(c1);
		} catch (Exception e) {
			throw new InvalidCryptoDataException("[SM2:Decrypt]invalid encrypt data, c1 invalid", e);
		}

		this.alternateKeyPoint = c1Point.multiply(decryptKey);
		resetKey();

		for (int i = 0; i < c2.length; i++) {
			if (alternateKeyOff >= alternateKey.length) {
				nextKey();
			}
			c2[i] ^= alternateKey[alternateKeyOff++];
		}
		this.c3Digest.update(c2, 0, c2.length);
		byte p[] = CommonUtils.byteConvert32Bytes(alternateKeyPoint.normalize().getYCoord().toBigInteger());
		this.c3Digest.update(p, 0, p.length);
		byte[] verifyC3 = this.c3Digest.doFinal();
		if (!Arrays.equals(verifyC3, c3)) {
			throw new InvalidKeyException("[SM2:Decrypt]invalid key, c3 is not match");
		}
		resetKey();
		// 返回解密结果
		return c2;
	}

	/**
	 * 签名
	 * 
	 * @param userId		用户ID
	 * @param prvKeyBytes	私钥
	 * @param sourceData	数据
	 * @return 签名数据{r, s}
	 */
	private final BigInteger[] sign(byte[] userId, byte[] prvKeyBytes, byte[] sourceData) {
		if (prvKeyBytes == null || prvKeyBytes.length == 0) {
			throw new InvalidCryptoParamsException("[SM2:sign]prvKeyBytes is null");
		}
		if (sourceData == null || sourceData.length == 0) {
			throw new InvalidCryptoParamsException("[SM2:sign]sourceData is null");
		}
		// 私钥, 私钥和基点生成秘钥点
		BigInteger key = new BigInteger(prvKeyBytes);
		ECPoint keyPoint = pointG.multiply(key);
		// Z
		Sm3Digest digest = new Sm3Digest();
		byte[] z = getZ(userId, keyPoint);
		// 对数据做摘要
		digest.update(z, 0, z.length);
		digest.update(sourceData);
		byte[] digestData = digest.doFinal();
		// 签名数据{r, s}
		return signInner(digestData, key, keyPoint);
	}
	
	public final byte[] sign(byte[] prvKeyBytes, byte[] sourceData) {
		BigInteger[] bigIntegers = sign(DEFAULT_USER_ID, prvKeyBytes, sourceData);
		byte[] rBytes = modifyRSFixedBytes(bigIntegers[0].toByteArray());
		byte[] sBytes = modifyRSFixedBytes(bigIntegers[1].toByteArray());
		byte[] signBytes = new byte[rBytes.length + sBytes.length];
        System.arraycopy(rBytes, 0, signBytes, 0,  rBytes.length);
        System.arraycopy(sBytes, 0, signBytes, rBytes.length, sBytes.length);
		return signBytes;
	}

	/**
     * 将R或者S修正为固定字节数
     * @param rs
     * @return
     */
    private static byte[] modifyRSFixedBytes(byte[] rs) {
        int length = rs.length;
        int fixedLength = 32;
        byte[] result = new byte[fixedLength];
        if (length < 32) {
            System.arraycopy(rs, 0, result, fixedLength - length, length);
        } else {
            System.arraycopy(rs, length - fixedLength, result, 0, fixedLength);
        }
        return result;
    }
    
	/**
	 * 签名(ASN.1编码)
	 * 
	 * @param userId		用户ID
	 * @param prvKeyBytes	私钥
	 * @param sourceData	数据
	 * @return 签名数据 byte[] ASN.1编码
	 */
	protected final byte[] signToASN1(byte[] userId, byte[] prvKeyBytes, byte[] sourceData) {
		if (prvKeyBytes == null || prvKeyBytes.length == 0) {
			throw new InvalidCryptoParamsException("[SM2:signToASN1]prvKeyBytes is null");
		}
		if (sourceData == null || sourceData.length == 0) {
			throw new InvalidCryptoParamsException("[SM2:signToASN1]sourceData is null");
		}
		BigInteger[] signData = sign(userId, prvKeyBytes, sourceData);
		// 签名数据序列化
		ASN1Integer derR = new ASN1Integer(signData[0]);// r
		ASN1Integer derS = new ASN1Integer(signData[1]);// s
		ASN1EncodableVector vector = new ASN1EncodableVector();
		vector.add(derR);
		vector.add(derS);
		DERSequence sign = new DERSequence(vector);
		try {
			return sign.getEncoded(ASN1Encoding.DER);
		} catch (IOException e) {
			return null;
		}
	}
	
	/**
	 * 签名(ASN.1编码)
	 * 
	 * @param prvKeyBytes	私钥
	 * @param sourceData	数据
	 * @return 签名数据 byte[] ASN.1编码
	 */
	public final byte[] signToASN1(byte[] prvKeyBytes, byte[] sourceData) {
		return signToASN1(DEFAULT_USER_ID, prvKeyBytes, sourceData);
	}

	private final BigInteger[] signInner(byte[] digestData, BigInteger key, ECPoint keyPoint) {
		BigInteger e = new BigInteger(1, digestData);
		BigInteger k;
		ECPoint kp;
		BigInteger r;
		BigInteger s;
		do {
			do {
				// 正式环境
				AsymmetricCipherKeyPair keypair = keyPairGenerator.generateKeyPair();
				ECPrivateKeyParameters privateKey = (ECPrivateKeyParameters) keypair.getPrivate();
				ECPublicKeyParameters publicKey = (ECPublicKeyParameters) keypair.getPublic();
				k = privateKey.getD();
				kp = publicKey.getQ();
				// 固定随机数测试
				//String kS = "6CB28D99385C175C94F94E934817663FC176D925DD72B727260DBAAE1FB2F96F";
		        //k = new BigInteger(kS, 16);
		        //kp = this.pointG.multiply(k);
				// r
				r = e.add(kp.normalize().getXCoord().toBigInteger());
				r = r.mod(SM2_ECC_N);
			} while (r.equals(BigInteger.ZERO) || r.add(k).equals(SM2_ECC_N));
			// (1 + dA)~-1
			BigInteger da_1 = key.add(BigInteger.ONE);
			da_1 = da_1.modInverse(SM2_ECC_N);
			// s
			s = r.multiply(key);
			s = k.subtract(s).mod(SM2_ECC_N);
			s = da_1.multiply(s).mod(SM2_ECC_N);
		} while (s.equals(BigInteger.ZERO));

		return new BigInteger[] { r, s };
	}
	
	/**
	 * 验签
	 * 
	 * @param userId		用户ID
	 * @param pubKeyBytes		公钥
	 * @param sourceData	数据
	 * @param signR			签名数据r
	 * @param signS			签名数据s
	 * @return true:签名有效,false:签名无效
	 */
	private final boolean verifySign(byte[] userId, byte[] pubKeyBytes, byte[] sourceData, BigInteger signR, BigInteger signS) throws InvalidKeyException {
		if (pubKeyBytes == null || pubKeyBytes.length == 0) {
			throw new InvalidCryptoParamsException("[SM2:verifySign]key is null");
		}
		if (sourceData == null || sourceData.length == 0 || signR == null || signS == null) {
			return false;
		}

		// 公钥
		ECPoint key;
		try {
			key = curve.decodePoint(pubKeyBytes);
		} catch (Exception e) {
			throw new InvalidKeyException("[SM2:verifySign]invalid public key (format)", e);
		}
		// Z
		Sm3Digest digest = new Sm3Digest();
		byte[] z = getZ(userId, key);
		// 对数据摘要
		digest.update(z, 0, z.length);
		digest.update(sourceData, 0, sourceData.length);
		byte[] digestData = digest.doFinal();
		// 验签
		return signR.equals(verifyInner(digestData, key, signR, signS));
	}
	
	public final boolean verifySign(byte[] pubKeyBytes, byte[] sourceData, byte[] signData) throws InvalidSignDataException, InvalidKeyException {
		 //获取签名
        BigInteger R = null;
        BigInteger S = null;
        byte[] rBy = new byte[33];
        System.arraycopy(signData, 0, rBy, 1, 32);
        rBy[0] = 0x00;
        byte[] sBy = new byte[33];
        System.arraycopy(signData, 32, sBy, 1, 32);
        sBy[0] = 0x00;
        R = new BigInteger(rBy);
        S = new BigInteger(sBy);
		return verifySign(DEFAULT_USER_ID, pubKeyBytes, sourceData, R, S);
	}

	/**
	 * 验签(ASN.1编码签名)
	 * 
	 * @param userId		用户ID
	 * @param pubKeyBytes	公钥
	 * @param sourceData	数据
	 * @param signData		签名数据(ASN.1编码)
	 * @return true:签名有效,false:签名无效
	 * @throws InvalidSignDataException	ASN.1编码无效
	 * @throws InvalidCryptoDataException 
	 * @throws InvalidKeyException 
	 */
	@SuppressWarnings("unchecked")
	protected final boolean verifySignByASN1(byte[] userId, byte[] pubKeyBytes, byte[] sourceData, byte[] signData) throws InvalidSignDataException, InvalidKeyException {
		byte[] _signData = signData;

		// 过滤头部的0x00
		int startIndex = 0;
		for (int i = 0; i < signData.length; i++) {
			if (signData[i] != 0x00) {
				break;
			}
			startIndex++;
		}
		if (startIndex > 0) {
			_signData = new byte[signData.length - startIndex];
			System.arraycopy(signData, startIndex, _signData, 0, _signData.length);
		}

		ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(_signData);
		ASN1InputStream asn1InputStream = new ASN1InputStream(byteArrayInputStream);
		
		Enumeration<ASN1Integer> signObj;
		ASN1Object derObj;
		ASN1Object endObj;
		try {
			derObj = asn1InputStream.readObject();
			endObj = asn1InputStream.readObject();
			if(endObj != null) {
				throw new InvalidSignDataException("[SM2:decrypt:ASN1]invalid sign data (ASN.1)");
			}
			signObj = ((ASN1Sequence) derObj).getObjects();
		} catch (IOException e) {
			throw new InvalidSignDataException("[SM2:verifySign]invalid sign data (ASN.1)", e);
		} finally {
			IOUtils.closeQuietly(byteArrayInputStream);
			IOUtils.closeQuietly(asn1InputStream);
		}
		
		
		BigInteger r = signObj.nextElement().getValue();
		BigInteger s = signObj.nextElement().getValue();

		// 验签
		return verifySign(userId, pubKeyBytes, sourceData, r, s);
	}

	/**
	 * 验签(ASN.1编码签名)
	 * 
	 * @param userId		 用户ID
	 * @param pubKeyBytes	公钥
	 * @param sourceData	数据
	 * @param signData		签名数据(ASN.1编码)
	 * @return true:签名有效,false:签名无效
	 * @throws InvalidKeyException 
	 * @throws InvalidSignDataException	ASN.1编码无效
	 * @throws InvalidCryptoDataException 
	 */
	public final boolean verifySignByASN1(byte[] pubKeyBytes, byte[] sourceData, byte[] signData) throws InvalidSignDataException, InvalidKeyException {
		return verifySignByASN1(DEFAULT_USER_ID, pubKeyBytes, sourceData, signData);
	}
	
	private final BigInteger verifyInner(byte digestData[], ECPoint userKey, BigInteger r, BigInteger s) {
		BigInteger e = new BigInteger(1, digestData);
		BigInteger t = r.add(s).mod(SM2_ECC_N);
		if (t.equals(BigInteger.ZERO)) {
			return null;
		} else {
			ECPoint x1y1 = pointG.multiply(s);
			x1y1 = x1y1.add(userKey.multiply(t));
			return e.add(x1y1.normalize().getXCoord().toBigInteger()).mod(SM2_ECC_N);
		}
	}
	
	class Sm2EncryptedData {

		private ECPoint c1;
		
		private byte[] c2;
		
		private byte[] c3;
		
		public Sm2EncryptedData(ECPoint c1, byte[] c2, byte[] c3) {
			this.c1 = c1;
			this.c2 = c2;
			this.c3 = c3;
		}
		
		public ECPoint getC1() {
			return c1;
		}

		public void setC1(ECPoint c1) {
			this.c1 = c1;
		}

		public byte[] getC2() {
			return c2;
		}

		public void setC2(byte[] c2) {
			this.c2 = c2;
		}

		public byte[] getC3() {
			return c3;
		}

		public void setC3(byte[] c3) {
			this.c3 = c3;
		}

	}

}
