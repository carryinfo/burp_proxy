package burp;

import java.text.SimpleDateFormat;
import java.util.Date;

public class Utils {

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
