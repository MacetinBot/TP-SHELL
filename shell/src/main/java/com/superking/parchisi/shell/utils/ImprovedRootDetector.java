package com.superking.parchisi.shell.utils;

import android.content.Context;
import android.content.pm.PackageManager;
import android.provider.Settings;
import android.text.TextUtils;
import com.superking.parchisi.shell.helpers.SystemPropertiesHelper;

import java.io.*;

public class ImprovedRootDetector {
  
  public static boolean isDeviceSecure(Context context) {
    return performStealthSecurityCheck(context) == 0;
  }
  
  private static int performStealthSecurityCheck(Context context) {
    // Early exit: apenas detecta, retorna
    if (checkRootBinariesStealthily()) return 1;
    if (checkMagiskArtifacts()) return 1;
    if (checkRootAppsAndEnvironment(context)) return 1;
    if (checkSystemPropertiesAndIntegrity()) return 1;
    if (checkFileSystemAndMounts()) return 1;
    if (checkDeveloperAndDebugSettings(context)) return 1;
    if (checkHooksAndFrameworks()) return 1;
    if (checkEnvironmentVariables()) return 1;
    if (checkRunningProcesses()) return 1;
    if (checkAppProcessIntegrity()) return 1;
    if (checkSelinuxStatus()) return 1;
    if (checkKnoxStatus()) return 1;
    if (checkVirtualizationApps(context)) return 1;
    
    return 0;
  }
  
  private static boolean checkRootBinariesStealthily() {
    String[] rootPaths = {
            "/system/bin/su", "/system/xbin/su", "/sbin/su", "/system/sbin/su",
            "/system/app/Superuser.apk", "/system/bin/busybox", "/system/xbin/busybox",
            "/data/local/xbin/su", "/data/local/bin/su", "/data/local/su",
            "/su/bin/su", "/system/xbin/daemonsu", "/system/xbin/su-old"
    };
    for (String path : rootPaths) {
      if (new File(path).exists()) return true;
    }
    
    String buildTags = SystemPropertiesHelper.getSystemPropertySilently("ro.build.tags");
    return !TextUtils.isEmpty(buildTags) &&
            (buildTags.contains("test-keys") || buildTags.contains("dev-keys"));
  }
  
  private static boolean checkMagiskArtifacts() {
    String[] magiskPaths = {
            "/data/adb/magisk", "/data/adb/modules", "/cache/.magisk",
            "/dev/.magisk", "/sbin/.magisk", "/sbin/.core/img",
            "/data/unencrypted/magisk", "/system/etc/init/magisk.rc",
            "/system/bin/.magisk", "/system/xbin/.magisk"
    };
    for (String path : magiskPaths) {
      if (new File(path).exists()) return true;
    }
    
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
    
    String hardware = SystemPropertiesHelper.getSystemPropertySilently("ro.hardware").toLowerCase();
    String model = SystemPropertiesHelper.getSystemPropertySilently("ro.product.model").toLowerCase();
    String product = SystemPropertiesHelper.getSystemPropertySilently("ro.product.name").toLowerCase();
    
    return hardware.contains("goldfish") || hardware.contains("ranchu") ||
            model.contains("emulator") || product.contains("sdk");
  }
  
  private static boolean checkSystemPropertiesAndIntegrity() {
    if (SystemPropertiesHelper.isDebuggableBuild()) return true;
    
    if (!SystemPropertiesHelper.isBootVerified()) {
      String verifiedBootState = SystemPropertiesHelper.getSystemPropertySilently("ro.boot.verifiedbootstate");
      if ("orange".equals(verifiedBootState) || "red".equals(verifiedBootState)) {
        return true;
      }
    }
    
    String[][] criticalProps = {
            {"ro.secure", "1"},
            {"ro.build.selinux", "1"},
            {"ro.boot.flash.locked", "1"},
            {"ro.boot.veritymode", "enforcing"}
    };
    
    for (String[] prop : criticalProps) {
      if (!SystemPropertiesHelper.checkSystemProperty(prop[0], prop[1])) {
        String actualValue = SystemPropertiesHelper.getSystemPropertySilently(prop[0]);
        if (!TextUtils.isEmpty(actualValue)) return true;
      }
    }
    return false;
  }
  
  private static boolean checkFileSystemAndMounts() {
    String[] rwPaths = {"/system", "/system/bin", "/system/sbin", "/system/xbin", "/vendor"};
    for (String path : rwPaths) {
      if (isDirectoryWritable(path)) return true;
    }
    
    try (BufferedReader br = new BufferedReader(new FileReader("/proc/mounts"))) {
      String line;
      while ((line = br.readLine()) != null) {
        if (line.contains("/dev/block/loop") || (line.contains("rw,") && line.contains("/system"))) {
          return true;
        }
      }
    } catch (Exception ignored) {}
    return false;
  }
  
  private static boolean checkDeveloperAndDebugSettings(Context context) {
    try {
      int devOptionsEnabled = Settings.Global.getInt(context.getContentResolver(),
              Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0);
      int adbEnabled = Settings.Global.getInt(context.getContentResolver(),
              Settings.Global.ADB_ENABLED, 0);
      if (devOptionsEnabled == 1 || adbEnabled == 1) return true;
    } catch (SecurityException ignored) {}
    
    String[][] adbProps = {
            {"init.svc.adbd", "running"},
            {"service.adb.root", "1"},
            {"persist.service.adb.enable", "1"},
            {"ro.adb.secure", "0"}
    };
    for (String[] prop : adbProps) {
      if (SystemPropertiesHelper.checkSystemProperty(prop[0], prop[1])) return true;
    }
    return false;
  }
  
  private static boolean checkHooksAndFrameworks() {
    String[] frameworkPaths = {
            "/system/framework/XposedBridge.jar",
            "/system/lib/libsubstrate.so", "/system/lib64/libsubstrate.so",
            "/data/local/tmp/frida-server", "/data/local/tmp/frida-server-64"
    };
    for (String path : frameworkPaths) {
      if (new File(path).exists()) return true;
    }
    return false;
  }
  
  private static boolean checkAppProcessIntegrity() {
    String appProcessPath = "/system/bin/app_process";
    String appProcessOriginal32 = "/system/bin/app_process32";
    String appProcessOriginal64 = "/system/bin/app_process64";
    
    try {
      File appProcess = new File(appProcessPath);
      // Verifica si es un enlace simbólico o si no existe el original
      if (!appProcess.exists()) return true;
      
      // Comprueba si es un enlace simbólico (común en roots)
      String canonicalPath = appProcess.getCanonicalPath();
      String absolutePath = appProcess.getAbsolutePath();
      if (!canonicalPath.equals(absolutePath)) {
        return true;
      }
      
      // Verifica la existencia de los binarios originales
      File appProcess32 = new File(appProcessOriginal32);
      File appProcess64 = new File(appProcessOriginal64);
      if (!appProcess32.exists() && !appProcess64.exists()) {
        return true;
      }
      
      // Opcional: Verificar permisos sospechosos (ej: writable por todos)
      if (appProcess.canWrite()) {
        return true;
      }
    } catch (Exception ignored) {
      // Si hay error al acceder, asumir sospechoso (opcional, según tu política)
      return true;
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
    } catch (Exception ignored) {
      return false;
    }
  }
  
  private static boolean checkRunningProcesses() {
    String[] criticalProcesses = {"magiskd", "daemonsu", "su", "frida-server"};
    File procDir = new File("/proc");
    File[] pids = procDir.listFiles();
    if (pids == null) return false;
    
    for (File pid : pids) {
      if (!pid.isDirectory()) continue;
      String name = pid.getName();
      int pidNum;
      try {
        pidNum = Integer.parseInt(name);
      } catch (NumberFormatException e) {
        continue; // no es un PID válido
      }
      if (pidNum > 50000) continue; // evitar escanear procesos muy altos
      
      String cmdLine = readFirstLine("/proc/" + pidNum + "/cmdline");
      if (cmdLine == null) continue;
      
      for (String process : criticalProcesses) {
        if (cmdLine.contains(process)) {
          return true;
        }
      }
    }
    return false;
  }
  
  private static boolean checkSelinuxStatus() {
    String selinuxStatus = SystemPropertiesHelper.getSystemPropertySilently("sys.fs.selinux.enforce");
    return "0".equals(selinuxStatus);
  }
  
  private static boolean checkKnoxStatus() {
    String manufacturer = SystemPropertiesHelper.getSystemPropertySilently("ro.product.manufacturer");
    if (!"samsung".equalsIgnoreCase(manufacturer)) return false;
    
    String knoxStatus = SystemPropertiesHelper.getSystemPropertySilently("ro.boot.warranty_bit");
    return "1".equals(knoxStatus) || "true".equals(knoxStatus);
  }
  
  private static boolean checkVirtualizationApps(Context context) {
    String[] virtualizationPackages = {
            "com.lbe.parallel.intl",
            "com.oasisfeng.island",
            "com.exiom.cloaky",
            "com.catchingnow.icebox"
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
  
  private static boolean isDirectoryWritable(String path) {
    try {
      File dir = new File(path);
      if (!dir.canWrite()) return false;
      
      File testFile = new File(dir, ".t_" + System.nanoTime());
      if (testFile.createNewFile()) {
        testFile.delete();
        return true;
      }
    } catch (Exception ignored) {}
    return false;
  }
  
  private static String readFirstLine(String filePath) {
    try (BufferedReader reader = new BufferedReader(new FileReader(filePath))) {
      return reader.readLine();
    } catch (Exception e) {
      return null;
    }
  }
}