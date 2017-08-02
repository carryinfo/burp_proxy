package burp;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Map;

public class Utils {

    public static void replaceMapValue(Map<String, String> map, String key, String value){
        if(map != null && map.containsKey(key)){
            map.replace(key, value);
        }
    }

    public static void removeMapPair(Map<String, ?> map, String key){
        if(map != null && map.containsKey(key)){
            map.remove(key);
        }
    }

    public static String getMD5(String str) {
        try {
            // 生成一个MD5加密计算摘要
            MessageDigest md = MessageDigest.getInstance("MD5");
            // 计算md5函数
            md.update(str.getBytes());
            // digest()最后确定返回md5 hash值，返回值为8为字符串。因为md5 hash值是16位的hex值，实际上就是8位的字符
            // BigInteger函数则将8位的字符串转换成16位hex值，用字符串来表示；得到字符串形式的hash值
//            return byteArrayToHexStr(md.digest());
//            CommonLog.logd("digest: " + new String(md.digest()));
//            CommonLog.logd(byteArrayToHexStr(md.digest()));
//            return new BigInteger(1, md.digest()).toString(16);

            StringBuffer hexString = new StringBuffer();
            byte[] hash = md.digest();

            for (int i = 0; i < hash.length; i++) {
                if ((0xff & hash[i]) < 0x10) {
                    hexString.append("0"
                            + Integer.toHexString((0xFF & hash[i])));
                } else {
                    hexString.append(Integer.toHexString(0xFF & hash[i]));
                }
            }
            return hexString.toString();

        } catch (Exception e) {

        }
        return null;
    }

    public static String byteArrayToHexStr(byte[] byteArray) {
        if (byteArray == null){
            return null;
        }

        StringBuffer buffer = new StringBuffer();
        char[] hexArray = "0123456789ABCDEF".toCharArray();
        for(byte b: byteArray){
            buffer.append(String.format("0x%02x, ", b));
        }


//        char[] hexChars = new char[byteArray.length * 2];
//        for (int j = 0; j < byteArray.length; j++) {
//            int v = byteArray[j] & 0xFF;
//            hexChars[j * 2] = hexArray[v >>> 4];
//            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
//        }
        return buffer.toString();
    }

    public static String getCurrentTime(){
        Date now = new Date();
        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        return dateFormat.format( now );
    }

}
