/*
* @author: your grandma
* */
package burp;

import java.io.*;
import java.net.URLDecoder;
import java.util.*;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

import static burp.IInterceptedProxyMessage.ACTION_DONT_INTERCEPT;
import static burp.IInterceptedProxyMessage.ACTION_DO_INTERCEPT;


public class BurpExtender implements IBurpExtender, IHttpListener, IProxyListener
{

    private IExtensionHelpers mHelper;

    private boolean mLogging = false;

    private IBurpExtenderCallbacks mCallback = null;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
    {
        // set our extension name
        callbacks.setExtensionName("burp proxy");
        CommonLog.logd("burp extender, register");

        mCallback = callbacks;

        mHelper = callbacks.getHelpers();

        callbacks.registerHttpListener(this);
//        callbacks.registerProxyListener(this);
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        synchronized (BurpExtender.this){

            IHttpService service = messageInfo.getHttpService();
            String host = service.getHost();
            if(host != null && !host.toLowerCase().contains("facebook")){
                return;
            }

            if(messageIsRequest){
                processRequest(messageInfo);
            }else{
                processResponse(messageInfo);
            }
        }
    }
//
//    private void replaceHWInfo(byte[] data, IRequestInfo reqInfo){
//        List<String> headers = reqInfo.getHeaders();
//
//        URL url = reqInfo.getUrl();
//        String s = url.toString();
//
//        for(String header: headers){
//            if(header.contains("abc")){
//                CommonLog.logd("abc;;;;; ");
//
//               header =  header.replace("abc", "def");
//            }
//            CommonLog.logd(header);
//        }
//
//        int offset = reqInfo.getBodyOffset();
//        byte[] body = arrayCopy(data, offset);
//
//    }

    void processRequest(IHttpRequestResponse msgInfo){

        mCallback.setProxyInterceptionEnabled(true);

        CommonLog.logd(">>> before replaceHWInfo");
        dumpMessage(true, msgInfo);

        msgInfo = replaceHWInfo(msgInfo);
        CommonLog.logd(">>> end replaceHWInfo");
        dumpMessage(true, msgInfo);


        mCallback.setProxyInterceptionEnabled(false);


        if(mLogging){
            dumpMessage(true, msgInfo);
        }
    }

    void processResponse(IHttpRequestResponse msgInfo){
        if(mLogging){
            dumpMessage(false, msgInfo);
        }

    }

    private byte[] arrayCopy(byte[] data, int offset){
        byte[] copy = new byte[data.length - offset];
        for (int i = 0; i < copy.length; i++){
            copy[i] = data[i + offset];
        }
        return copy;
    }

    // decompress
    public static String gzipDecompress(byte[] data) {
        if (data == null || data.length == 0) {
            return null;
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ByteArrayInputStream in = new ByteArrayInputStream(data);

        try {
            GZIPInputStream gunzip = new GZIPInputStream(in);
            int n;
            while ((n = gunzip.read(buffer))>= 0) {
                out.write(buffer, 0, n);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        return new String(buffer);
    }

    private byte[] gzipCompress(String str) {
        if (str == null || str.length() == 0) {
            return null;
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        GZIPOutputStream gzip;
        try {
            gzip = new GZIPOutputStream(out);
            gzip.write(str.getBytes());
            gzip.close();
        } catch (IOException e) {
        }
        return out.toByteArray();
    }

    private static byte[] buffer = new byte[1024 * 1024];

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


        String md5 = Utils.getMD5(encodedMessage);

//        for i in digest_message:
//        k = 0xFF & ord(i)
//        arr.append(chr(CONST_ARRAY[(k >> 4)]))
//        arr.append(chr(CONST_ARRAY[(k & 0xF)]))
//        sig = ''.join(arr)
        return md5;
    }

    private String bodyModify4FB(String payload){
        String res = new String();

        String[] values = payload.split("&");
        Map<String, String> keyvalue = new HashMap<>();


        for(String item: values){
            String[] s = item.split("=");
            if(s.length == 2){
                if(!keyvalue.containsKey(s[0])){
                    keyvalue.put(s[0], s[1]);
                }
            }
        }

        boolean hasSig = keyvalue.containsKey("sig");

        Utils.removeMapPair(keyvalue, "sig");

        Utils.replaceMapValue(keyvalue, "email", "lifengeng@163.com");
        Utils.replaceMapValue(keyvalue, "password", "dahiad");
        Utils.replaceMapValue(keyvalue, "device_id", "ae11efe2-5a03-4a97-9a5d-68b54fbc61fb");
        Utils.replaceMapValue(keyvalue, "reg_instance", "ae11efe2-5a03-4a97-9a5d-68b54fbc61fb");
        Utils.replaceMapValue(keyvalue, "family_device_id", "ae11efe2-5a03-4a97-9a5d-68b54fbc61fb");
        Utils.replaceMapValue(keyvalue, "firstname", "li");
        Utils.replaceMapValue(keyvalue, "lastname", "fengeng");
//        Utils.replaceMapValue(keyvalue, "adid", "4f4ae35e2f432b63");
//        Utils.replaceMapValue(keyvalue, "generate_session_cookies", "false");
//        Utils.removeMapPair(keyvalue, "advertising_id");
//        Utils.removeMapPair(keyvalue, "generate_machine_id");
//        Utils.removeMapPair(keyvalue, "adid");
//        CommonLog.logd("getSignature input: " + keyvalue.toString());
        String sig = getSignature(keyvalue);
        if(hasSig){
            CommonLog.logd("sig: " + sig);
            keyvalue.put("sig", sig);
        }

        Utils.replaceMapValue(keyvalue, "email", "lifengeng%40163.com");

        for(Map.Entry<String, String> item: keyvalue.entrySet()){
            res = res + item.getKey() + "=" + item.getValue() + "&";
        }
        res = res.substring(0, res.length() - 1);

        return res;
    }

    private List<String> headerModify4FB(List<String> headers){
        List<String> res = new ArrayList<>();

        String AGENT = "user-agent: Dalvik/1.6.0 (Linux; U; Android 4.3; GT-I9308 Build/JSS15J) " +
                "[FBAN/FB4A;FBAV/120.0.0.18.72;FBPN/com.facebook.katana;" +
                "FBLC/zh_CN;FBBV/55510008;FBCR/null;FBMF/samsung;FBBD/samsung;" +
                "FBDV/GT-I9308;FBSV/4.3;FBCA/armeabi-v7a:armeabi;" +
                "FBDM/{density=2.0,width=720,height=1280};FB_FW/1;]";

        for(String item: headers){
            if(item.toLowerCase().contains("user-agent")){
                res.add(AGENT);
            }else{
                res.add(item);
            }
        }

        return res;
    }

    private IHttpRequestResponse replaceHWInfo(IHttpRequestResponse messageInfo) {
        byte[] data = messageInfo.getRequest();
        IHttpService service = messageInfo.getHttpService();
        IRequestInfo reqInfo = mHelper.analyzeRequest(service, data);
        List<String> headers = reqInfo.getHeaders();
        int offset = reqInfo.getBodyOffset();
        byte[] body = arrayCopy(data, offset);

        List<String> reqHeader = null;
        byte[] reqBody = null;

        {
            // header
            reqHeader = headerModify4FB(headers);
//            CommonLog.logd("reqHeader: " + reqHeader.toString());
        }

        {
            // body
            boolean gzip = false;
            String payload = null;
            if (body.length >= 2 && body[0] == (byte) 0x1f && body[1] == (byte) 0x8b) {
                // gzip
                payload = gzipDecompress(body);
                gzip = true;
            }else{
                payload = new String(body);
            }

//            CommonLog.logd("decompress: " + payload);
            payload = bodyModify4FB(payload);
//            CommonLog.logd("after bodyModify4FB: " + payload);

            if(gzip){
                // compress
                reqBody = gzipCompress(payload);
//                CommonLog.logd("after gzipCompress: " + payload);
            }else{
                reqBody = payload.getBytes();
            }
        }

        byte[] reqMsg = mHelper.buildHttpMessage(reqHeader, reqBody);
//        CommonLog.logd("reqMsg: " + reqMsg.toString());
        messageInfo.setRequest(reqMsg);
        return messageInfo;
    }


    private void dumpMessage(boolean messageIsRequest, IHttpRequestResponse msgInfo){
        if(messageIsRequest){
            IHttpService service = msgInfo.getHttpService();
            byte[] data = msgInfo.getRequest();
            IRequestInfo reqInfo = mHelper.analyzeRequest(service, data);

            CommonLog.logd("");
            CommonLog.logd("REQ >>>");
            CommonLog.logd(reqInfo.getUrl().toString());
            CommonLog.logd(Utils.getCurrentTime());
            CommonLog.logd("");
            List<String> headers = reqInfo.getHeaders();
            for(String header: headers){
                CommonLog.logd(header);
            }

            CommonLog.logd("");

            int offset = reqInfo.getBodyOffset();
            byte[] body = arrayCopy(data, offset);
            if(body.length >= 2 && body[0] == (byte)0x1f && body[1] == (byte)0x8b){
                String out = gzipDecompress(body);
                CommonLog.logd(URLDecoder.decode(out));
            }else{
                CommonLog.logd(URLDecoder.decode(new String(body)));
            }
            CommonLog.logd("");
        } else{
            byte[] data = msgInfo.getResponse();
            IResponseInfo resInfo = mHelper.analyzeResponse(data);
            CommonLog.logd("");
            CommonLog.logd("RES <<<");
            CommonLog.logd(Utils.getCurrentTime());
            CommonLog.logd("");
            List<String> headers = resInfo.getHeaders();
            for(String header: headers){
                CommonLog.logd(header);
            }

            CommonLog.logd("");

            int offset = resInfo.getBodyOffset();
            byte[] body = arrayCopy(data, offset);

            if(body.length >= 2 && body[0] == (byte)0x1f && body[1] == (byte)0x8b){
                String out = gzipDecompress(body);
                CommonLog.logd(URLDecoder.decode(out));
            }else{
                CommonLog.logd(URLDecoder.decode(new String(body)));
            }
            CommonLog.logd("");
        }
    }

    @Override
    public void processProxyMessage(boolean messageIsRequest, IInterceptedProxyMessage message) {
        if(messageIsRequest){
            IHttpService service = message.getMessageInfo().getHttpService();
            String host = service.getHost();
            if(host != null && !host.toLowerCase().contains("facebook")){
                return;
            }

            if(message.getInterceptAction() != ACTION_DO_INTERCEPT){
                message.setInterceptAction(ACTION_DO_INTERCEPT);
            }


            IHttpRequestResponse msgInfo = message.getMessageInfo();
            CommonLog.logd("before replaceHWInfo");
            dumpMessage(messageIsRequest, msgInfo);

            msgInfo = replaceHWInfo(msgInfo);
            CommonLog.logd("end replaceHWInfo");
            dumpMessage(messageIsRequest, msgInfo);
            message.setInterceptAction(ACTION_DONT_INTERCEPT);
        }
    }
}