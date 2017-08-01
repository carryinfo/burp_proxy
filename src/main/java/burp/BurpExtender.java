/*
* @author: your grandma
* */
package burp;

import java.io.*;
import java.net.URLDecoder;
import java.util.List;
import java.util.zip.GZIPInputStream;

import static burp.IInterceptedProxyMessage.ACTION_DONT_INTERCEPT;
import static burp.IInterceptedProxyMessage.ACTION_DO_INTERCEPT;


public class BurpExtender implements IBurpExtender, IHttpListener, IProxyListener
{

    private IExtensionHelpers mHelper;

    private boolean mLogging = false;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
    {
        // set our extension name
        callbacks.setExtensionName("burp proxy");
        CommonLog.logd("burp extender, register");

        mHelper = callbacks.getHelpers();

//        callbacks.registerHttpListener(this);
        callbacks.registerProxyListener(this);

    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        synchronized (BurpExtender.this){
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
        IHttpService service = msgInfo.getHttpService();
        byte[] data = msgInfo.getRequest();
        IRequestInfo reqInfo = mHelper.analyzeRequest(service, data);

        if(mLogging){
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
//        CommonLog.logd("offset: " + offset);
            byte[] body = arrayCopy(data, offset);

//        CommonLog.logd(Utils.byteArrayToHexStr(body));


            if(body.length >= 2 && body[0] == (byte)0x1f && body[1] == (byte)0x8b){
//            CommonLog.logd("gzip");
                String out = gzipDecompress(body);
                CommonLog.logd(URLDecoder.decode(out));
            }else{
                CommonLog.logd(URLDecoder.decode(new String(body)));
            }
            CommonLog.logd("");
        }


    }

    void processResponse(IHttpRequestResponse msgInfo){
        IHttpService service = msgInfo.getHttpService();

        String host = service.getHost();
        if(host != null && !host.toLowerCase().contains("facebook")){
            return;
        }

        byte[] data = msgInfo.getResponse();
        IResponseInfo resInfo = mHelper.analyzeResponse(data);
        if(mLogging){
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

    private static byte[] buffer = new byte[1024 * 1024];

    private IHttpRequestResponse replaceHWInfo(IHttpRequestResponse messageInfo) {
        String message = new String(messageInfo.getRequest());
        String search = "abc";
        String replace = "def";
        StringBuilder newString = new StringBuilder(message.length() - search.length() + replace.length());
        try {
            BufferedReader reader = new BufferedReader(new StringReader(message));
            String line;

            while ((line = reader.readLine()) != null) {
                if (line != null) {
                    if (line.contains(search)) {
                        line = line.replaceAll(search, replace);
                    }
                    newString.append(line).append("\r\n");
                }
            }
        } catch (Exception e) {
        }

        messageInfo.setRequest(newString.toString().getBytes());
        return messageInfo;
    }


    @Override
    public void processProxyMessage(boolean messageIsRequest, IInterceptedProxyMessage message) {
        if(messageIsRequest){
            if(message.getInterceptAction() != ACTION_DO_INTERCEPT){
                message.setInterceptAction(ACTION_DO_INTERCEPT);
            }

            IHttpRequestResponse msgInfo = message.getMessageInfo();

            msgInfo = replaceHWInfo(msgInfo);
            message.setInterceptAction(ACTION_DONT_INTERCEPT);
        }
    }
}