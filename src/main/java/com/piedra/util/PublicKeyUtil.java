package com.piedra.util;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.IOUtils;

import javax.crypto.Cipher;
import java.io.InputStream;
import java.security.Key;
import java.security.KeyFactory;
import java.security.spec.X509EncodedKeySpec;

/**
 * 公钥加解密方法
 *
 * @author linwb
 * @since 2017-06-02
 */
public class PublicKeyUtil {
    private static PublicKeyUtil util;
    private String publicKey ;

    private PublicKeyUtil() {
        InputStream in = null;
        try {
            in = PublicKeyUtil.class.getClassLoader().getResourceAsStream("keypair/RSAPublic.key");
            publicKey = IOUtils.readLines(in).get(0);
        } catch (Exception e) {
            IOUtils.closeQuietly(in);
        }
    }


    public static PublicKeyUtil getInstance() {
        if (util != null) {
            return util;
        }
        synchronized (PublicKeyUtil.class) {
            if (util == null) {
                util = new PublicKeyUtil();
            }
        }
        return util;
    }


    /**
     * 用公钥解密
     *
     * @param data 待解密数据
     * @param key  公钥
     * @return 返回解密后的字节数组
     */
    private byte[] decryptByPublicKey(byte[] data, String key) throws Exception {
        // 对密钥解密
        byte[] keyBytes = Base64.decodeBase64(key);
        // 取得公钥
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(RSAConstants.KEY_ALGORITHM);
        Key publicKey = keyFactory.generatePublic(x509KeySpec);
        // 对数据解密
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.DECRYPT_MODE, publicKey);
        return cipher.doFinal(data);
    }


    /**
     * 用公钥加密
     *
     * @param data 待加密数据
     * @param key  公钥
     * @return 返回加密后的字节数组
     */
    private byte[] encryptByPublicKey(String data, String key) throws Exception {
        // 对公钥解密
        byte[] keyBytes = Base64.decodeBase64(key);
        // 取得公钥
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(RSAConstants.KEY_ALGORITHM);
        Key publicKey = keyFactory.generatePublic(x509KeySpec);
        // 对数据加密
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(data.getBytes());
    }


    public String encrypt(String data) throws Exception {
        return Base64.encodeBase64String(encryptByPublicKey(data, publicKey));
    }
}
