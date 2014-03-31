package my.util.encryp.all;
import sun.misc.BASE64Decoder;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class AESCrypt {
    private final static String[] strDigits = { "0", "1", "2", "3", "4", "5",
            "6", "7", "8", "9", "a", "b", "c", "d", "e", "f" };
    private static String byteToArrayString(byte bByte) {
        int iRet = bByte;
        // System.out.println("iRet="+iRet);
        if (iRet < 0) {
            iRet += 256;
        }
        int iD1 = iRet / 16;
        int iD2 = iRet % 16;
        return strDigits[iD1] + strDigits[iD2];
    }

    // 转换字节数组为16进制字串
    private static String byteToString(byte[] bByte) {
        StringBuffer sBuffer = new StringBuffer();
        for (int i = 0; i < bByte.length; i++) {
            sBuffer.append(byteToArrayString(bByte[i]));
        }
        return sBuffer.toString();
    }
    /*
     * 加密
     *
     * @param content
     * 需要加密的内容
     * @param password
     * 加密密码
     * @return
     */
    public  String encrypt(String content, String password) {
        try {
            System.out.println("传入的明文：" + content);
            System.out.println("传入的密钥：" + password);
            //KeyGenerator提供对策密钥生成器的功能,支持各种算法
            KeyGenerator kgen = KeyGenerator.getInstance( "AES" );
            SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG" );
            secureRandom.setSeed(password.getBytes());
//            kgen.init(128,secureRandom);
            kgen.init(128,new SecureRandom(password.getBytes()));
            //获取密匙对象
           // SecretKey skey = kgen.generateKey();

            //获取随机密匙
         //   byte[] raw = skey.getEncoded();

            //初始化SecretKeySpec对象
           // SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES");


            // SecretKey 负责保存对称密钥
            SecretKey secretKey = kgen.generateKey();

            byte[] enCodeFormat = secretKey.getEncoded();

            byte[] intArr;
//使用静态初始化，初始化数组时只指定数组元素的初始值，不指定数组长度。
            intArr = "03AC674216F3E15C761EE1A5E255F067953623C8B388B4459E13F978D7C846F4".getBytes("utf-8");
            //System.out.println(""+byteToString(intArr));

//            SecretKeySpec key = new SecretKeySpec(enCodeFormat, "AES");
            SecretKeySpec key = new SecretKeySpec(sha256eccrypt(password), "AES");

            //System.out.println("转换后的密钥：" + key.getEncoded());
            //System.out.println(""+byteToString(key.getEncoded()));
            // 创建密码器
            Cipher cipher = Cipher.getInstance("AES");
            byte[] byteContent = content.getBytes("utf-8");
            System.out.print("明文转utf-8后的byte：");
            for(int i = 0;i<byteContent.length;i++){
                System.out.print(byteContent[i] + " ");
            }
            System.out.println();
            // 初始化
            cipher.init(Cipher.ENCRYPT_MODE, key);
            // 加密
            byte[] result = cipher.doFinal(byteContent);
            //return parseByte2HexStr(result);
            System.out.print("加密后的byte：");
            for(int i = 0;i<result.length;i++){
                System.out.print(result[i] + " ");
            }
            System.out.println();
            System.out.println("加密后的：" + (new sun.misc.BASE64Encoder()).encode(result));
            return (new sun.misc.BASE64Encoder()).encode(result);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        }
        return new String();
    }

    /*
     * 注意：解密的时候要传入byte数组
     * 解密
     * @param content
     * 待解密内容
     * @param password
     * 解密密钥
     * @return
     */
    //public  String decrypt(byte[] content, String password) {
    public  String decrypt(String contentStr, String password) {
        try {
            byte[] content = (new sun.misc.BASE64Decoder()).decodeBuffer(contentStr);
            for(int i = 0;i<content.length;i++){
                System.out.print(content[i]);
            }
            System.out.println();

            KeyGenerator kgen = KeyGenerator.getInstance( "AES" );
            SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG" );
            secureRandom.setSeed(password.getBytes());
            kgen.init(128,secureRandom);
            SecretKey secretKey = kgen.generateKey();

            byte[] enCodeFormat = secretKey.getEncoded();
            SecretKeySpec key = new SecretKeySpec(enCodeFormat, "AES");
            // 创建密码器
            Cipher cipher = Cipher.getInstance("AES");
            // 初始化
            cipher.init(Cipher.DECRYPT_MODE, key);
            // 加密
            byte[] result = cipher.doFinal(content);
            return new String(result);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (Exception e){
            e.printStackTrace();
        }
        return new String();
    }

    public static void main(String[] args) throws Exception {
        String content = "99999999";
        String pwd = "1234";
        //7110EDA4D09E062AA5E4A390B0A572AC0D2C0220
        //a4b6157319038724e3560894f7f932c8886ebfcfc2c374a83de852eb3bf660cc
        //03AC674216F3E15C761EE1A5E255F067953623C8B388B4459E13F978D7C846F4
        AESCrypt ac = new AESCrypt();
        System.out.println("sha256:" + byteToString(ac.sha256eccrypt(pwd)));
        String afterEDS = ac.encrypt(content, pwd);
        System.out.println(afterEDS);
        System.out.println(ac.decrypt(afterEDS, pwd));
       // System.out.println(ac.decrypt("EQyz+ukU+ss+Sinf15bApdYj5ANrRwY632v8EhrzLPk=", pwd));


        System.out.println((new sun.misc.BASE64Encoder()).encode("欢迎光临JerryVon的博客".getBytes()));
        //加密串就是5qyi6L+O5YWJ5Li0SmVycnlWb27nmoTljZrlrqI=
        System.out.println(new String((new BASE64Decoder()).decodeBuffer("5qyi6L+O5YWJ5Li0SmVycnlWb27nmoTljZrlrqI=")));

    }

    public byte[] sha256eccrypt(String info) throws NoSuchAlgorithmException{
        MessageDigest md5 = MessageDigest.getInstance("SHA-256");
        byte[] srcBytes = info.getBytes();
        //使用srcBytes更新摘要
        md5.update(srcBytes);
        //完成哈希计算，得到result
        byte[] resultBytes = md5.digest();
        return resultBytes;
    }
}
