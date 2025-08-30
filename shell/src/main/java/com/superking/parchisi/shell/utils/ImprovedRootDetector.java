package com.superking.parchisi.shell.utils;

import android.content.Context;
import android.content.pm.PackageManager;
import android.provider.Settings;
import android.text.TextUtils;
import com.superking.parchisi.shell.helpers.SystemPropertiesHelper;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.io.RandomAccessFile;

public class ImprovedRootDetector {
  
  public static boolean isDeviceSecure(Context context) {
    return performStealthSecurityCheck(context) == 0;
  }
  
  private static int performStealthSecurityCheck(Context context) {
    int riskIndicators = 0;
    
    // Verificaciones críticas (cualquiera de estas falla = dispositivo comprometido)
    if (checkRootBinariesStealthily()) riskIndicators++;
    if (checkMagiskArtifacts()) riskIndicators++;
    if (checkRootAppsAndEnvironment(context)) riskIndicators++;
    if (checkSystemPropertiesAndIntegrity()) riskIndicators++;
    if (checkFileSystemAndMounts()) riskIndicators++;
    if (checkDeveloperAndDebugSettings(context)) riskIndicators++;
    if (checkHooksAndFrameworks()) riskIndicators++;
    if (checkEnvironmentVariables()) riskIndicators++;
    if (checkRunningProcesses()) riskIndicators++; // Verificación de procesos
    if (checkSelinuxStatus()) riskIndicators++; // Verificación de SELinux
    if (checkKnoxStatus()) riskIndicators++; // Verificación de Knox (Samsung)
    if (checkVirtualizationApps(context)) riskIndicators++; // Apps de virtualización
    
    return riskIndicators;
  }
  
  private static boolean checkRootBinariesStealthily() {
    String[] rootPaths = {
            "/system/bin/su", "/system/xbin/su", "/sbin/su", "/system/sbin/su",
            "/system/app/Superuser.apk", "/system/bin/busybox", "/system/xbin/busybox",
            "/data/local/xbin/su", "/data/local/bin/su", "/data/local/su",
            "/su/bin/su", "/system/xbin/daemonsu", "/system/xbin/su-old"
    };
    for (String path : rootPaths) {
      if (fileExistsStealthily(path)) return true;
    }
    
    // Build tags usando el helper
    String buildTags = SystemPropertiesHelper.getSystemPropertySilently("ro.build.tags");
    return !TextUtils.isEmpty(buildTags) && (
            buildTags.contains("test-keys") || buildTags.contains("dev-keys")
    );
  }
  
  private static boolean checkMagiskArtifacts() {
    String[] magiskPaths = {
            "/data/adb/magisk", "/data/adb/modules", "/cache/.magisk",
            "/dev/.magisk", "/sbin/.magisk", "/sbin/.core/img",
            "/data/unencrypted/magisk", "/system/etc/init/magisk.rc",
            "/system/bin/.magisk", "/system/xbin/.magisk"
    };
    for (String path : magiskPaths) {
      if (fileExistsStealthily(path)) return true;
    }
    
    // Propiedades de Magisk usando el helper
    String bootMode = SystemPropertiesHelper.getSystemPropertySilently("ro.boot.mode");
    String magiskVersion = SystemPropertiesHelper.getSystemPropertySilently("ro.magisk.version");
    return "magisk".equals(bootMode) || !TextUtils.isEmpty(magiskVersion);
  }
  
  private static boolean checkRootAppsAndEnvironment(Context context) {
    String[] rootPackages = {
            "com.topjohnwu.magisk", "eu.chainfire.supersu", "com.noshufou.android.su",
            "com.koushikdutta.superuser", "com.thirdparty.superuser",
            "com.ramdroid.rootapp", "com.zachspong.temprootremovejb",
            "de.robv.android.xposed.installer", "com.saurik.substrate",
            "com.kingroot.kinguser", "com.kingroot.master"
    };
    PackageManager pm = context.getPackageManager();
    for (String pkg : rootPackages) {
      try {
        pm.getPackageInfo(pkg, 0);
        return true;
      } catch (PackageManager.NameNotFoundException ignored) {}
    }
    
    // Emuladores usando propiedades del helper
    String hardware = SystemPropertiesHelper.getSystemPropertySilently("ro.hardware").toLowerCase();
    String model = SystemPropertiesHelper.getSystemPropertySilently("ro.product.model").toLowerCase();
    String product = SystemPropertiesHelper.getSystemPropertySilently("ro.product.name").toLowerCase();
    
    return hardware.contains("goldfish") || hardware.contains("ranchu") ||
            model.contains("emulator") || product.contains("sdk");
  }
  
  private static boolean checkSystemPropertiesAndIntegrity() {
    // Usando métodos especializados del helper
    if (SystemPropertiesHelper.isDebuggableBuild()) {
      return true;
    }
    
    if (!SystemPropertiesHelper.isBootVerified()) {
      // Verificar estados problemáticos
      String verifiedBootState = SystemPropertiesHelper.getSystemPropertySilently("ro.boot.verifiedbootstate");
      if ("orange".equals(verifiedBootState) || "red".equals(verifiedBootState)) {
        return true;
      }
    }
    
    // Otras propiedades críticas usando el helper
    String[][] criticalProps = {
            {"ro.secure", "1"},
            {"ro.build.selinux", "1"},
            {"ro.boot.flash.locked", "1"},
            {"ro.boot.veritymode", "enforcing"}
    };
    
    for (String[] prop : criticalProps) {
      if (!SystemPropertiesHelper.checkSystemProperty(prop[0], prop[1])) {
        String actualValue = SystemPropertiesHelper.getSystemPropertySilently(prop[0]);
        if (!TextUtils.isEmpty(actualValue)) {
          return true;
        }
      }
    }
    
    return false;
  }
  
  private static boolean checkFileSystemAndMounts() {
    String[] rwPaths = {"/system", "/system/bin", "/system/sbin", "/system/xbin", "/vendor"};
    for (String path : rwPaths) {
      if (isDirectoryWritable(path)) return true;
    }
    
    // Montajes sospechosos
    String mounts = readFile("/proc/mounts");
    return !TextUtils.isEmpty(mounts) && (
            mounts.contains("/dev/block/loop") ||
                    (mounts.contains("rw,") && mounts.contains("/system"))
    );
  }
  
  private static boolean checkDeveloperAndDebugSettings(Context context) {
    try {
      int devOptionsEnabled = Settings.Global.getInt(
              context.getContentResolver(),
              Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0
      );
      int adbEnabled = Settings.Global.getInt(
              context.getContentResolver(),
              Settings.Global.ADB_ENABLED, 0
      );
      if (devOptionsEnabled == 1 || adbEnabled == 1) return true;
    } catch (SecurityException ignored) {}
    
    // Propiedades ADB usando el helper
    String[][] adbProps = {
            {"init.svc.adbd", "running"},
            {"service.adb.root", "1"},
            {"persist.service.adb.enable", "1"},
            {"ro.adb.secure", "0"}
    };
    
    for (String[] prop : adbProps) {
      if (SystemPropertiesHelper.checkSystemProperty(prop[0], prop[1])) {
        return true;
      }
    }
    
    return false;
  }
  
  private static boolean checkHooksAndFrameworks() {
    // Xposed/Substrate/Frida
    String[] frameworkPaths = {
            "/system/framework/XposedBridge.jar",
            "/system/lib/libsubstrate.so", "/system/lib64/libsubstrate.so",
            "/data/local/tmp/frida-server", "/data/local/tmp/frida-server-64"
    };
    for (String path : frameworkPaths) {
      if (fileExistsStealthily(path)) return true;
    }
    return false;
  }
  
  private static boolean checkEnvironmentVariables() {
    try {
      String path = System.getenv("PATH");
      if (path != null && (path.contains("/sbin") || path.contains("/system/xbin"))) {
        return true;
      }
      String ldPreload = System.getenv("LD_PRELOAD");
      return !TextUtils.isEmpty(ldPreload);
    } catch (Exception e) {
      return false;
    }
  }
  
  private static boolean checkRunningProcesses() {
    try {
      // Verifica procesos críticos directamente en /proc
      String[] criticalProcesses = {"magiskd", "daemonsu", "su", "frida-server"};
      File procDir = new File("/proc");
      File[] pids = procDir.listFiles();
      if (pids != null) {
        for (File pid : pids) {
          if (!pid.isDirectory()) continue;
          try {
            int pidNum = Integer.parseInt(pid.getName());
            String cmdLine = readFile("/proc/" + pidNum + "/cmdline");
            for (String process : criticalProcesses) {
              if (cmdLine.contains(process)) {
                return true;
              }
            }
          } catch (NumberFormatException ignored) {}
        }
      }
    } catch (Exception e) {
      return false;
    }
    return false;
  }
  
  private static boolean checkSelinuxStatus() {
    String selinuxStatus = SystemPropertiesHelper.getSystemPropertySilently("sys.fs.selinux.enforce");
    return "0".equals(selinuxStatus); // 0 = permissive, 1 = enforcing
  }
  
  private static boolean checkKnoxStatus() {
    String manufacturer = SystemPropertiesHelper.getSystemPropertySilently("ro.product.manufacturer");
    if (!manufacturer.equalsIgnoreCase("samsung")) {
      return false;
    }
    
    // Knox 0x0 = no tripped, 0x1 = tripped
    String knoxStatus = SystemPropertiesHelper.getSystemPropertySilently("ro.boot.warranty_bit");
    return "1".equals(knoxStatus) || "true".equals(knoxStatus);
  }
  
  private static boolean checkVirtualizationApps(Context context) {
    String[] virtualizationPackages = {
            "com.lbe.parallel.intl", // Parallel Space
            "com.oasisfeng.island", // Island
            "com.exiom.cloaky", // Cloaky
            "com.catchingnow.icebox" // Ice Box
    };
    PackageManager pm = context.getPackageManager();
    for (String pkg : virtualizationPackages) {
      try {
        pm.getPackageInfo(pkg, 0);
        return true;
      } catch (PackageManager.NameNotFoundException ignored) {}
    }
    return false;
  }
  
  private static boolean fileExistsStealthily(String path) {
    try {
      RandomAccessFile file = new RandomAccessFile(path, "r");
      file.close();
      return true;
    } catch (Exception e) {
      return false;
    }
  }
  
  private static boolean isDirectoryWritable(String path) {
    try {
      File dir = new File(path);
      File testFile = new File(dir, ".test_" + System.currentTimeMillis());
      boolean created = testFile.createNewFile();
      if (created) {
        boolean deleted = testFile.delete();
        if (!deleted) {
          testFile.deleteOnExit();
        }
      }
      return created;
    } catch (Exception ignored) {}
    return false;
  }
  
  private static String readFile(String filePath) {
    try (FileInputStream fis = new FileInputStream(filePath);
         BufferedReader reader = new BufferedReader(new InputStreamReader(fis))) {
      StringBuilder content = new StringBuilder();
      String line;
      while ((line = reader.readLine()) != null) {
        content.append(line).append("\n");
      }
      return content.toString();
    } catch (Exception e) {
      return "";
    }
  }
}