package com.superking.parchisi.shell.helpers;

import android.annotation.SuppressLint;
import android.os.Build;
import android.text.TextUtils;
import android.util.Log;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;

public class SystemPropertiesHelper {
  
  private static final String TAG = "RootDetector";
  private static final Map<String, String> PROPERTY_MAPPINGS = new HashMap<>();
  
  static {
    // Mapeo específico para detección de root
    PROPERTY_MAPPINGS.put("ro.build.version.sdk", Build.VERSION.SDK);
    PROPERTY_MAPPINGS.put("ro.build.tags", Build.TAGS != null ? Build.TAGS : "");
    PROPERTY_MAPPINGS.put("ro.product.manufacturer", Build.MANUFACTURER != null ? Build.MANUFACTURER : "");
    PROPERTY_MAPPINGS.put("ro.product.model", Build.MODEL != null ? Build.MODEL : "");
    PROPERTY_MAPPINGS.put("ro.product.brand", Build.BRAND != null ? Build.BRAND : "");
    PROPERTY_MAPPINGS.put("ro.product.device", Build.DEVICE != null ? Build.DEVICE : "");
  }
  
  @SuppressLint("PrivateApi")
  public static String getSystemPropertySilently(String property) {
    // Primero verifica si tenemos un mapeo directo
    if (PROPERTY_MAPPINGS.containsKey(property)) {
      return PROPERTY_MAPPINGS.get(property);
    }
    
    // Para propiedades críticas de detección de root
    switch (property) {
      case "ro.debuggable":
      case "ro.boot.verifiedbootstate":
      case "ro.boot.flash.locked":
      case "ro.boot.veritymode":
      case "ro.build.selinux":
      case "ro.secure":
      case "ro.magisk.version":
      case "ro.boot.mode":
      case "sys.fs.selinux.enforce":
      case "ro.boot.warranty_bit":
      case "init.svc.adbd":
      case "service.adb.root":
      case "persist.service.adb.enable":
      case "ro.adb.secure":
        return getPropertyViaReflection(property);
      default:
        return "";
    }
  }
  
  @SuppressLint("PrivateApi")
  private static String getPropertyViaReflection(String property) {
    try {
      Class<?> systemProperties = Class.forName("android.os.SystemProperties");
      Method getMethod = systemProperties.getMethod("get", String.class);
      Object result = getMethod.invoke(null, property);
      return result != null ? result.toString() : "";
      
    } catch (ClassNotFoundException e) {
      Log.d(TAG, "SystemProperties not available");
      return "";
    } catch (NoSuchMethodException e) {
      Log.d(TAG, "SystemProperties.get method not found");
      return "";
    } catch (IllegalAccessException | InvocationTargetException e) {
      Log.d(TAG, "Access denied to SystemProperties");
      return "";
    } catch (Exception e) {
      return "";
    }
  }
  
  // Método adicional útil para tu detector de root
  public static boolean checkSystemProperty(String property, String expectedValue) {
    String actualValue = getSystemPropertySilently(property);
    return !TextUtils.isEmpty(actualValue) && expectedValue.equals(actualValue);
  }
  
  // Método específico para ro.debuggable (común en detección de root)
  public static boolean isDebuggableBuild() {
    String debuggable = getSystemPropertySilently("ro.debuggable");
    return "1".equals(debuggable);
  }
  
  // Método específico para verifiedbootstate
  public static boolean isBootVerified() {
    String bootState = getSystemPropertySilently("ro.boot.verifiedbootstate");
    return "green".equals(bootState);
  }
}