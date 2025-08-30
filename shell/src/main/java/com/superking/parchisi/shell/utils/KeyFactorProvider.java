package com.superking.parchisi.shell.utils;

import android.content.Context;

public interface KeyFactorProvider {
  String getFactor(Context context) throws Exception;
}