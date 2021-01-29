package com.example.encryptionalgorithmspits;

import de.robv.android.xposed.XposedBridge;

public class YenKocUtil {
    public static void KeyAndAlgorithmlog(String packname,String sr,byte[] key)
    {
        XposedBridge.log("YenKocCRY "+"packname:"+packname+"|加密算法:"+sr+":"+HexDumper.dumpHexString(key));
    }
    public static void Ivlog(String packname,String sr,byte[] iv)
    {
        XposedBridge.log("YenKocCRY "+"packname:"+packname+"|"+sr+":"+HexDumper.dumpHexString(iv));
    }
    public static String GetStack()
    {
        String result = "";
        Throwable ex = new Throwable();
        StackTraceElement[] stackElements = ex.getStackTrace();
        if (stackElements != null) {

            int range_start = 5;
            int range_end = Math.min(stackElements.length,7);
            if(range_end < range_start)
                return  "";

            for (int i = range_start; i < range_end; i++) {

                result = result + (stackElements[i].getClassName()+"->");
                result = result + (stackElements[i].getMethodName())+"  ";
                result = result + (stackElements[i].getFileName()+"(");
                result = result + (stackElements[i].getLineNumber()+")\n");
                result = result + ("-----------------------------------\n");
            }
        }
        return result;
    }
}
