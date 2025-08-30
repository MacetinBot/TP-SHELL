package com.superking.parchisi.shell.utils;

import android.content.Context;
import android.util.Base64;

public class PackageNameProvider implements KeyFactorProvider {
  
  @Override
  public String getFactor(Context context) throws Exception {
    String packageName = context.getPackageName();
    String expectedPrefix = new String(Base64.decode("Y29tLnN1cGVya2luZy5wYXJjaGlzaQ==", Base64.DEFAULT));
    
    if (!packageName.startsWith(expectedPrefix)) {
      throw new Exception();
    }
    
    String remainingPart = packageName.substring(expectedPrefix.length());
    
    if (remainingPart.isEmpty()) {
      return expectedPrefix;
    }
    
    if (remainingPart.startsWith(".")) {
      remainingPart = remainingPart.substring(1);
    }
    
    if (!remainingPart.isEmpty()) {
      
      int nextDotIndex = remainingPart.indexOf(".");
      String nextSegment = (nextDotIndex != -1) ? remainingPart.substring(0, nextDotIndex) : remainingPart;
      
      String segmentSuffix = nextSegment.length() >= 2 ? nextSegment.substring(0, 2) : nextSegment;
      
      return expectedPrefix + "." + segmentSuffix;
    }
    
    return expectedPrefix;
  }
}