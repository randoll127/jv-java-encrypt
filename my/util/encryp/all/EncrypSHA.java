package my.util.encryp.all;

import my.util.encryp.md5.MD5Utils;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class EncrypSHA {
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

    public byte[] eccrypt(String info,String shaType) throws NoSuchAlgorithmException{
        MessageDigest sha = MessageDigest.getInstance(shaType);
        byte[] srcBytes = info.getBytes();
        //使用srcBytes更新摘要
        sha.update(srcBytes);
        //完成哈希计算，得到result
        byte[] resultBytes = sha.digest();
        return resultBytes;
    }
    public byte[] eccryptSHA1(String info) throws NoSuchAlgorithmException{
       return eccrypt(info,"SHA1");
    }
    public byte[] eccryptSHA256(String info) throws NoSuchAlgorithmException{
        return eccrypt(info,"SHA-256");
    }
    public byte[] eccryptSHA384(String info) throws NoSuchAlgorithmException{
        return eccrypt(info,"SHA-384");
    }
    public byte[] eccryptSHA512(String info) throws NoSuchAlgorithmException{
        return eccrypt(info,"SHA-512");
    }
	public static void main(String[] args) throws NoSuchAlgorithmException {
		String msg ="欢迎光临JerryVon的博客";
		EncrypSHA sha = new EncrypSHA();
		System.out.println("明文是：" + msg);
		System.out.println("密文是：" + MD5Utils.hexString(sha.eccryptSHA1(msg)));
        System.out.println("密文是：" + MD5Utils.hexString(sha.eccryptSHA256(msg)));
        System.out.println("密文是：" + MD5Utils.hexString(sha.eccryptSHA384(msg)));
        System.out.println("密文是：" + MD5Utils.hexString(sha.eccryptSHA512(msg)));
	}

}
