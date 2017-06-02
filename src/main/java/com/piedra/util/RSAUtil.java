package com.piedra.util;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.FileUtils;

import java.io.File;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Collections;

/**
 * RSA密钥对生成工具类
 *
 * @author linwb
 * @since 2017-06-02
 */
public class RSAUtil {

//    /**
//     * 用私钥对信息进行加密生成数字签名
//     *
//     * @param data       加密数据
//     * @param privateKey 私钥
//     * @return  返回数字签名
//     * @throws Exception    异常抛出
//     */
//    public static String sign(byte[] data, String privateKey) throws Exception {
//        // 解密由base64编码的私钥
//        byte[] keyBytes = Base64.decodeBase64(privateKey);
//
//        // 构造PKCS8EncodedKeySpec对象
//        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
//        // KEY_ALGORITHM 指定的加密算法
//        KeyFactory keyFactory = KeyFactory.getInstance(RSAConstants.KEY_ALGORITHM);
//        // 取私钥匙对象
//        PrivateKey priKey = keyFactory.generatePrivate(pkcs8KeySpec);
//
//        // 用私钥对信息生成数字签名
//        Signature signature = Signature.getInstance(RSAConstants.SIGNATURE_ALGORITHM);
//        signature.initSign(priKey);
//        signature.update(data);
//        return Base64.encodeBase64String(signature.sign());
//    }
//
//    /**
//     * 校验数字签名
//     * @param data      加密数据
//     * @param publicKey 公钥
//     * @param sign      数字签名
//     * @return 校验成功返回true 失败返回false
//     * @throws Exception
//     */
//    public static boolean verify(byte[] data, String publicKey, String sign) throws Exception {
//        // 解密由base64编码的公钥
//        byte[] keyBytes = Base64.decodeBase64(publicKey);
//
//        // 构造X509EncodedKeySpec对象
//        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
//        // KEY_ALGORITHM 指定的加密算法
//        KeyFactory keyFactory = KeyFactory.getInstance(RSAConstants.KEY_ALGORITHM);
//        // 取公钥匙对象
//        PublicKey pubKey = keyFactory.generatePublic(keySpec);
//
//        Signature signature = Signature.getInstance(RSAConstants.SIGNATURE_ALGORITHM);
//        signature.initVerify(pubKey);
//        signature.update(data);
//        // 验证签名是否正常
//        return signature.verify(Base64.decodeBase64(sign));
//    }
//
//    /**
//     * 利用私钥解密
//     * @param data  待解密数据
//     * @param key   私钥
//     * @return      返回解密后的字节数组
//     * @throws Exception
//     */
//    public static byte[] decryptByPrivateKey(byte[] data, String key) throws Exception {
//        // 对密钥解密
//        byte[] keyBytes = Base64.decodeBase64(key);
//        // 取得私钥
//        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
//        KeyFactory keyFactory = KeyFactory.getInstance(RSAConstants.KEY_ALGORITHM);
//        Key privateKey = keyFactory.generatePrivate(pkcs8KeySpec);
//        // 对数据解密
//        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
//        cipher.init(Cipher.DECRYPT_MODE, privateKey);
//        return cipher.doFinal(data);
//    }
//
//    /**
//     * 用私钥解密
//     * @param data  待解密数据
//     * @param key   私钥
//     * @return      返回解密后的字节数组
//     * @throws Exception
//     */
//    public static byte[] decryptByPrivateKey(String data, String key) throws Exception {
//        return decryptByPrivateKey(Base64.decodeBase64(data), key);
//    }
//
//    /**
//     * 用公钥解密
//     * @param data  待解密数据
//     * @param key   公钥
//     * @return      返回解密后的字节数组
//     * @throws Exception
//     */
//    public static byte[] decryptByPublicKey(byte[] data, String key) throws Exception {
//        // 对密钥解密
//        byte[] keyBytes = Base64.decodeBase64(key);
//        // 取得公钥
//        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);
//        KeyFactory keyFactory = KeyFactory.getInstance(RSAConstants.KEY_ALGORITHM);
//        Key publicKey = keyFactory.generatePublic(x509KeySpec);
//        // 对数据解密
//        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
//        cipher.init(Cipher.DECRYPT_MODE, publicKey);
//        return cipher.doFinal(data);
//    }
//
//    /**
//     * 用公钥加密
//     * @param data  待加密数据
//     * @param key   公钥
//     * @return      返回加密后的字节数组
//     * @throws Exception
//     */
//    public static byte[] encryptByPublicKey(String data, String key) throws Exception {
//        // 对公钥解密
//        byte[] keyBytes = Base64.decodeBase64(key);
//        // 取得公钥
//        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);
//        KeyFactory keyFactory = KeyFactory.getInstance(RSAConstants.KEY_ALGORITHM);
//        Key publicKey = keyFactory.generatePublic(x509KeySpec);
//        // 对数据加密
//        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
//        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
//        return cipher.doFinal(data.getBytes());
//    }
//
//    /**
//     * 用私钥加密
//     * @param data  待加密数据
//     * @param key   私钥
//     * @return      返回加密后的字节数组
//     * @throws Exception
//     */
//    public static byte[] encryptByPrivateKey(byte[] data, String key) throws Exception {
//        // 对密钥解密
//        byte[] keyBytes = Base64.decodeBase64(key);
//        // 取得私钥
//        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
//        KeyFactory keyFactory = KeyFactory.getInstance(RSAConstants.KEY_ALGORITHM);
//        Key privateKey = keyFactory.generatePrivate(pkcs8KeySpec);
//        // 对数据加密
//        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
//        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
//        return cipher.doFinal(data);
//    }
//
//
    public static void main(String[] args) throws Exception {
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance(RSAConstants.KEY_ALGORITHM);
        keyPairGen.initialize(2048);
        KeyPair keyPair = keyPairGen.generateKeyPair();

        String publicKey = Base64.encodeBase64String(keyPair.getPublic().getEncoded());
        String privateKey = Base64.encodeBase64String(keyPair.getPrivate().getEncoded());


        FileUtils.writeLines(new File("c:/"+RSAConstants.PUBLIC_KEY), Collections.singleton(publicKey),"UTF-8",false);
        FileUtils.writeLines(new File("c:/"+RSAConstants.PRIVATE_KEY), Collections.singleton(privateKey),"UTF-8",false);


//        String cont = "你好，中国";
//        String enc = Base64.encodeBase64String(encryptByPublicKey(cont, publicKey));
//        System.out.println(enc);
//        System.out.println(new String(decryptByPrivateKey(enc, privateKey)));
    }

}
