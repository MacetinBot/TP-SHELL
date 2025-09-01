package com.superking.parchisi.shell.utils;

import android.content.Context;

public class SecurityProvider implements KeyFactorProvider {
  @Override
  public String getFactor(Context context) {
    boolean isRooted = !ImprovedRootDetector.isDeviceSecure(context);
    return Boolean.toString(isRooted);
  }
}