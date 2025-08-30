package com.superking.parchisi.shell.utils;

import android.content.Context;

public class SecurityProvider implements KeyFactorProvider {
  @Override
  public String getFactor(Context context) throws Exception {
    boolean isRooted = !ImprovedRootDetector.isDeviceSecure(context);
    return Boolean.toString(isRooted);
  }
}