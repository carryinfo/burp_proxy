package burp;

import java.io.UnsupportedEncodingException;
import java.util.HashMap;
import java.util.Map;
import java.util.SortedSet;
import java.util.TreeSet;

import static burp.BurpExtender.gzipDecompress;

public class test {
    public static void main(String args[]) {

        // 1
        byte[] data = {0x1f, (byte) 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4d, 0x50, 0x4b, 0x6e, 0x23, 0x21, 0x10, (byte) 0xbd, 0x0d, 0x3b, (byte) 0xb7, (byte) 0xfa, 0x07, (byte) 0xdd, 0x2c, 0x58, 0x44, 0x51, (byte) 0xa2, (byte) 0x89, 0x14, 0x65, (byte) 0x8e, (byte) 0x80, 0x0a, (byte) 0xaa, 0x70, 0x13, (byte) 0xd3, (byte) 0xe0, 0x01, (byte) 0x9c, (byte) 0xc8, 0x73, (byte) 0xfa, (byte) 0xc1, (byte) 0xce, 0x44, (byte) 0xca, (byte) 0xaa, (byte) 0xa0, (byte) 0xf4, (byte) 0xea, (byte) 0xfd, 0x76, (byte) 0xaa, (byte) 0xa0, 0x7d, 0x74, (byte) 0xda, (byte) 0x99, (byte) 0xbd, 0x3d, (byte) 0xd5, (byte) 0xdb, 0x6f, (byte) 0xfd, (byte) 0xfc, (byte) 0xf2, (byte) 0xfa, (byte) 0xc4, 0x00, 0x3d, 0x2a, (byte) 0xe0, 0x62, (byte) 0xea, (byte) 0xf9, (byte) 0xea, (byte) 0xd6, 0x69, (byte) 0x90, (byte) 0xdc, 0x0a, 0x62, 0x2e, (byte) 0xe5, 0x1d, (byte) 0xaa, 0x7a, 0x2f, 0x29, 0x32, (byte) 0xa4, 0x0f, 0x6f, 0x49, 0x37, (byte) 0xd8, (byte) 0xec, 0x0c, (byte) 0xa2, 0x10, 0x70, (byte) 0xb0, 0x60, (byte) 0xf9, 0x61, 0x5e, 0x08, 0x0f, 0x30, (byte) 0x9a, (byte) 0xe9, (byte) 0xc0, (byte) 0xa5, 0x1c, (byte) 0xa7, 0x65, 0x15, (byte) 0x96, 0x24, 0x31, (byte) 0xda, (byte) 0xc1, 0x07, 0x35, (byte) 0xf4, 0x7d, 0x3f, (byte) 0xf6, 0x5c, (byte) 0xf0, 0x5e, (byte) 0xca, 0x65, (byte) 0xe6, (byte) 0xec, 0x0c,
                (byte) 0xa5, 0x7c, (byte) 0xa6, (byte) 0x8c, 0x2a, (byte) 0xc6, (byte) 0xc8, 0x6c, 0x26, (byte) 0xa4, 0x58, 0x3d, (byte) 0x84, (byte) 0xa2, (byte) 0xeb, (byte) 0xf5, 0x4c, (byte) 0xea, (byte) 0xbf, (byte) 0x84, (byte) 0x81, 0x42, (byte) 0xa8, 0x43, 0x3a, (byte) 0xfa, (byte) 0xa8, (byte) 0xbf, 0x0f, (byte) 0xd8, (byte) 0x91, 0x22, 0x65, (byte) 0xa8,
                (byte) 0xa4, 0x0b, (byte) 0x95, (byte) 0xe2, 0x53, (byte) 0xd4, 0x36, (byte) 0xa5, (byte) 0x93, (byte) 0xa7, (byte) 0xa2,
                0x06, 0x46, 0x39, (byte) 0xa7, (byte) 0xac, (byte) 0xb1, (byte) 0xc5, (byte) 0xf1, (byte) 0xe1, (byte) 0x8b, (byte) 0xc8, 0x5c, 0x6a,
                0x6d, (byte) 0x90, 0x4f, 0x5f, 0x37, (byte) 0x8d, (byte) 0xbe, (byte) 0x80, 0x09, (byte) 0xf4, (byte) 0x83, 0x61, 0x07, (byte) 0xbb, (byte) 0xf9, 0x78,
                (byte) 0x8f, 0x32, (byte) 0xb0, (byte) 0x90, 0x2c, 0x04, 0x52, 0x7f, 0x37, (byte) 0xfd, (byte) 0xf8, (byte) 0xc6, 0x6c, (byte) 0xf0, (byte) 0xcd, 0x50, (byte) 0xa3, (byte) 0xbe,
                (byte) 0xc4, (byte) 0x9a, (byte) 0xaf, 0x6d, 0x22, (byte) 0xa9, (byte) 0xb6, 0x6e, 0x4d, 0x6d, (byte) 0xa9,
                (byte) 0xd5, 0x73, (byte) 0xa9, 0x5b, 0x77, (byte) 0xb7, (byte) 0xc5, (byte) 0x9c, (byte) 0xd1, 0x70, (byte) 0xf6, 0x3a, (byte) 0xd3, 0x1f, (byte) 0xed, 0x72, (byte) 0xbb, (byte) 0xc1, 0x70, (byte) 0xd5, 0x11, 0x76, (byte) 0xba, 0x63, 0x6e, (byte) 0x99, 0x6c, 0x13, (byte) 0xfa, 0x46, 0x35, (byte) 0x81, 0x40, 0x59, (byte) 0xdb, (byte) 0xd0, (byte) 0xb2, 0x28, (byte) 0x9b, (byte) 0xf6, (byte) 0xce, (byte) 0x81, 0x25, (byte) 0xd3, (byte) 0xec, 0x77, 0x27, (byte) 0xa8, 0x10, (byte) 0xa1, 0x2b, (byte) 0x94, 0x3f, 0x28, 0x77, 0x1b, 0x34, (byte) 0x9e, 0x36, (byte) 0x9f, (byte) 0xcd, 0x0c, 0x0f, (byte) 0x8d, (byte) 0xe7, (byte) 0xd7, (byte) 0xd7,
                (byte) 0x9f, (byte) 0xdd, 0x38, 0x4e, 0x74, 0x55, (byte) 0xeb, 0x3a, (byte) 0xc2, 0x3a, (byte) 0xcb, 0x7e, 0x12, 0x03, (byte) 0x82, 0x5c, (byte) 0x97, 0x7e, 0x34, 0x4e, 0x2e, (byte) 0xd0, (byte) 0x8f, 0x03, (byte) 0xa2, 0x1d, 0x66, 0x64, (byte) 0xc5, 0x1f, (byte) 0x95, 0x45, 0x27, (byte) 0xc4, (byte) 0xad, (byte) 0xf6, 0x75, (byte) 0xc5, 0x51, (byte) 0x92, (byte) 0x9c, 0x17, 0x2b, 0x70, (byte) 0xe4, (byte) 0xc3, (byte) 0xc2, 0x61, 0x12, 0x52, 0x2c, (byte) 0xff, 0x00, (byte) 0x81, 0x45, (byte) 0xc3, (byte) 0xdf, 0x01, 0x02, 0x00, 0x00};

        String out = gzipDecompress(data);
        CommonLog.logd(out);


        // 2

        Map<String, String> headers = new HashMap<>();

        headers.put("generate_machine_id", "true");
        headers.put("locale", "zh_CN");
        headers.put("family_device_id", "be11efe2-5a03-4a97-9a5d-68b54fbc61fb");
        headers.put("fb_api_req_friendly_name", "registerAccount");
        headers.put("generate_session_cookies", "true");
        headers.put("lastname", "feifei");
        headers.put("advertising_id", "a563058f83195c6e");
        headers.put("api_key", "882a8490361da98702bf97a021ddc14d");
        headers.put("email", "892364@qq.com");
        headers.put("meta_inf_fbmeta", "NO_FILE");
        headers.put("firstname", "xiao");
        headers.put("format", "json");
        headers.put("client_country_code", "CN");
        headers.put("return_multiple_errors", "true");
        headers.put("birthday", "1999-07-27");
        headers.put("password", "dahiad");
        headers.put("gender", "F");
        headers.put("device_id", "be11efe2-5a03-4a97-9a5d-68b54fbc61fb");
        headers.put("method", "user.register");
        headers.put("attempt_login", "true");
        headers.put("reg_instance", "be11efe2-5a03-4a97-9a5d-68b54fbc61fb");
        headers.put("fb_api_caller_class", "com.facebook.registration.fragment.RegistrationCreateAccountFragment");

        CommonLog.logd(getSignature(headers));

        // 3
        String p = "device_id=ae11efe2-5a03-4a97-9a5d-68b54fbc61fb&method=auth.login&generate_session_cookies=false&format=json&locale=zh_CN&fb_api_req_friendly_name=authenticate&password=dahiad&api_key=882a8490361da98702bf97a021ddc14d&meta_inf_fbmeta=NO_FILE&error_detail_type=button_with_disabled&email=lifengeng@163.com&credentials_type=password&client_country_code=CN&fb_api_caller_class=com.facebook.katana.server.handler.Fb4aAuthHandler";
//        CommonLog.logd();
    }

    private static String getSignature(Map<String, String> headers){
        String API_KEY = "882a8490361da98702bf97a021ddc14d";
        String API_SECRET = "62f8ce9f74b12f84c123cc23437a4a32";
        int[] CONST_ARRAY = {48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 97, 98, 99, 100, 101, 102};

        String message = new String();
        SortedSet<String> keys = new TreeSet<String>(headers.keySet());

        for(String key: keys){
            message = message + key + "=" + headers.get(key);
        }

        message += API_SECRET;
        String encodedMessage = null;
        try {
            encodedMessage = new String(message.getBytes("UTF-8"));
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }


        encodedMessage = "api_key=882a8490361da98702bf97a021ddc14dclient_country_code=CNcredentials_type=passworddevice_id=ae11efe2-5a03-4a97-9a5d-68b54fbc61fbemail=lifengeng@163.comerror_detail_type=button_with_disabledfb_api_caller_class=com.facebook.katana.server.handler.Fb4aAuthHandlerfb_api_req_friendly_name=authenticateformat=jsongenerate_session_cookies=falselocale=zh_CNmeta_inf_fbmeta=NO_FILEmethod=auth.loginpassword=dahiad62f8ce9f74b12f84c123cc23437a4a32";

        String md5 = Utils.getMD5(encodedMessage);

//        for i in digest_message:
//        k = 0xFF & ord(i)
//        arr.append(chr(CONST_ARRAY[(k >> 4)]))
//        arr.append(chr(CONST_ARRAY[(k & 0xF)]))
//        sig = ''.join(arr)
        return md5;
    }
}
