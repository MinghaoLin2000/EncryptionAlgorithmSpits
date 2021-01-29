package com.example.encryptionalgorithmspits;

import android.provider.CalendarContract;

import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

public class HookEncryption implements IXposedHookLoadPackage {

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lpparam) throws Throwable {
        if(lpparam.packageName.equals("com.example.xposedhook01"))
        {
            //hook AES加密
            //javax.crypto.Cipher
            Class cipheClass=XposedHelpers.findClass("javax.crypto.Cipher",lpparam.classLoader);
            XposedHelpers.findAndHookMethod(cipheClass, "getInstance", String.class, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    super.beforeHookedMethod(param);
                    Object[] objArray=param.args;
                    String cryptoMode=(String)objArray[0];
                    XposedBridge.log("YenKocCRY "+"packagename"+lpparam.packageName+"--"+ "加密模式:"+cryptoMode);
                }

                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    super.afterHookedMethod(param);
                }
            });
//             public SecretKeySpec(byte[] key, String algorithm) {
//            throw new RuntimeException("Stub!");
//        }
//
//    public SecretKeySpec(byte[] key, int offset, int len, String algorithm) {
//            throw new RuntimeException("Stub!");
//        }
            XposedBridge.hookAllConstructors(XposedHelpers.findClass("javax.crypto.spec.SecretKeySpec",lpparam.classLoader), new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    super.beforeHookedMethod(param);
                    int offset=0;
                    int len=0;
                    String algorithm="";
                    Object[] objArrays=param.args;
                    if(objArrays.length!=2)
                    {
                        offset=(int)objArrays[1];
                        len=(int)objArrays[2];
                        algorithm=(String)objArrays[3];
                    }else
                    {
                        algorithm=(String)objArrays[1];
                        len=((byte[])objArrays[0]).length;
                    }
                    byte[] data=new byte[len];
                    byte[] key=(byte[])objArrays[0];
                    System.arraycopy(key,offset,data,0,len);
                    String sr=algorithm+"|key";
                    YenKocUtil.KeyAndAlgorithmlog(lpparam.packageName,sr,data);
                    XposedBridge.log("YenKocCRY 栈信息:"+YenKocUtil.GetStack());
                }

                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    super.afterHookedMethod(param);
                }
            });
//             public IvParameterSpec(byte[] iv) {
//            throw new RuntimeException("Stub!");
//        }
//
//    public IvParameterSpec(byte[] iv, int offset, int len) {
//            throw new RuntimeException("Stub!");
//        }
            XposedBridge.hookAllConstructors(XposedHelpers.findClass("javax.crypto.spec.IvParameterSpec", lpparam.classLoader), new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    super.beforeHookedMethod(param);
                    int offset=0;
                    int len=0;
                    Object[] objectArray=param.args;
                    if(objectArray.length!=1)
                    {
                        offset=(int)objectArray[1];
                        len=(int)objectArray[2];
                    }
                    byte[] iv=(byte[])objectArray[0];
                    byte[] NewIvByte=new byte[len];
                    System.arraycopy(iv,offset,NewIvByte,0,len);
                    String ivstr="IV";
                    YenKocUtil.Ivlog(lpparam.packageName,ivstr,NewIvByte);
                    XposedBridge.log("YenKocCRY 栈信息:"+YenKocUtil.GetStack());

                }
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    super.afterHookedMethod(param);
                }
            });

            //md5
            XposedHelpers.findAndHookMethod(XposedHelpers.findClass("java.security.MessageDigest", lpparam.classLoader), "getInstance", String.class, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    super.beforeHookedMethod(param);
                    Object[] objArray=param.args;
                    String mode=(String)objArray[0];
                    XposedBridge.log("YenKocCRY|"+lpparam.packageName+"加密模式:"+mode);
                    XposedBridge.log("YenKocCRY 栈信息:"+YenKocUtil.GetStack());
                }

                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    super.afterHookedMethod(param);
                }
            });
            XposedHelpers.findAndHookMethod(XposedHelpers.findClass("java.security.MessageDigest", lpparam.classLoader), "digest", byte[].class, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    super.beforeHookedMethod(param);
                }

                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    super.afterHookedMethod(param);
                    Object[] arg=param.args;
                    String str=(String)arg[0];
                    String sec=(String)param.getResult();
                XposedBridge.log("明文 :"+str+"秘文 : "+sec);
                    XposedBridge.log("YenKocCRY 栈信息:"+YenKocUtil.GetStack());
                }
            });


        }

    }
}
