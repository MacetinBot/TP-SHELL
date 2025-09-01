package com.superking.parchisi.shell.utils;

import android.content.Context;
import android.hardware.Sensor;
import android.hardware.SensorManager;
import android.os.Build;
import android.provider.Settings;
import android.telephony.TelephonyManager;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.util.Arrays;

public class EmulatorDetectionProvider implements KeyFactorProvider {
  @Override
  public String getFactor(Context context) {
    return String.valueOf(isEmulator(context));
  }
  
  private boolean isEmulator(Context context) {
    return checkBuildProperties() ||
            checkSensors(context) ||
            checkEmulatorFiles() ||
            checkQemuProperties() ||
            checkTelephony(context) ||
            checkCpuInfo() ||
            checkDebugFlags(context);
  }
  
  private boolean checkBuildProperties() {
    return Build.BRAND.toLowerCase().contains("generic") ||
            Build.DEVICE.toLowerCase().contains("generic") ||
            Build.MODEL.toLowerCase().contains("sdk") ||
            Build.MANUFACTURER.toLowerCase().contains("genymotion") ||
            Build.HARDWARE.toLowerCase().matches(".*(goldfish|ranchu|vbox|qemu).*") ||
            Build.PRODUCT.toLowerCase().matches(".*(sdk|emulator|simulator).*") ||
            Build.FINGERPRINT.toLowerCase().contains("generic") ||
            (Build.TAGS != null && Build.TAGS.toLowerCase().contains("test-keys"));
  }
  
  private boolean checkSensors(Context context) {
    try {
      SensorManager sm = (SensorManager) context.getSystemService(Context.SENSOR_SERVICE);
      if (sm == null) return true;
      return sm.getSensorList(Sensor.TYPE_ALL).size() < 7;
    } catch (Exception e) {
      return false;
    }
  }
  
  private boolean checkEmulatorFiles() {
    String[] paths = {
            "/dev/socket/qemud", "/dev/qemu_pipe", "/system/lib/libdvm.so",
            "/sys/module/vboxguest", "/sys/module/vboxsf", "/proc/tty/drivers",
            "/dev/socket/genyd", "/dev/socket/baseband_genyd"
    };
    return Arrays.stream(paths).anyMatch(path -> new File(path).exists());
  }
  
  private boolean checkQemuProperties() {
    try {
      String[] props = {"ro.kernel.qemu", "ro.bootmode", "ro.hardware"};
      return Arrays.stream(props)
              .map(prop -> System.getProperty(prop, ""))   // "" si es null
              .anyMatch(v -> v != null &&
                      (v.contains("qemu") || v.contains("goldfish")));
    } catch (Exception e) {
      return false;
    }
  }
  
  private boolean checkTelephony(Context context) {
    try {
      TelephonyManager tm = (TelephonyManager) context.getSystemService(Context.TELEPHONY_SERVICE);
      if (tm == null) return true;
      String networkOperator = tm.getNetworkOperatorName();
      return "Android".equals(networkOperator) || networkOperator.isEmpty();
    } catch (Exception e) {
      return false;
    }
  }
  
  private boolean checkCpuInfo() {
    try (BufferedReader reader = new BufferedReader(new FileReader("/proc/cpuinfo"))) {
      String line;
      while ((line = reader.readLine()) != null) {
        if (line.toLowerCase().contains("intel") && line.toLowerCase().contains("atom")) {
          return true;
        }
      }
    } catch (Exception ignored) {}
    return false;
  }
  
  private boolean checkDebugFlags(Context context) {
    try {
      return Settings.Global.getInt(context.getContentResolver(),
              Settings.Global.ADB_ENABLED, 0) == 1;
    } catch (Exception e) {
      return false;
    }
  }
}