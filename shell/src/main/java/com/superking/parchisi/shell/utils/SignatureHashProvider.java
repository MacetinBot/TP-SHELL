package com.superking.parchisi.shell.utils;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;

import java.security.MessageDigest;

public class SignatureHashProvider implements KeyFactorProvider {
  
  @Override
  public String getFactor(Context context) throws Exception {
   
    PackageInfo packageInfo = context.getPackageManager().getPackageInfo(context.getPackageName(), PackageManager.GET_SIGNATURES);
    
    Signature[] signatures = packageInfo.signatures;
    if (signatures == null || signatures.length == 0) {
      throw new RuntimeException();
    }
    
    MessageDigest md = MessageDigest.getInstance("SHA-256");
    md.update(signatures[0].toByteArray());
    byte[] digest = md.digest();
    
    StringBuilder hexString = new StringBuilder();
    for (byte b : digest) {
      String hex = Integer.toHexString(0xFF & b);
      if (hex.length() == 1) {
        hexString.append('0');
      }
      hexString.append(hex);
    }
    return hexString.toString();
  }
}