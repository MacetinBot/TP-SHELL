package com.superking.parchisi.shell.utils;

import android.content.Context;
import android.util.Log;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

class FridaDetectionProvider implements KeyFactorProvider {
  private static final String TAG = "FridaDetector";
  private static final AtomicBoolean isDetected = new AtomicBoolean(false);
  
  @Override
  public String getFactor(Context context) throws Exception {
    if (isFridaDetected()) {
      Log.e(TAG, "Frida detectado! Cerrando aplicación...");
      killApp();
      throw new Exception("Frida detectado en el sistema"); // Esta línea nunca se alcanzará por killApp()
    }
    return "false"; // Retorna false si no se detecta Frida
  }
  
  private boolean isFridaDetected() {
    if (isDetected.get()) {
      return true;
    }
    
    // Lista de técnicas de detección
    List<DetectionTechnique> techniques = Arrays.asList(
            this::checkFridaPort,
            this::checkFridaFiles,
            this::checkFridaProcesses,
            this::checkFridaLibraries,
            this::checkFridaStringsInMaps,
            this::checkFridaTcpConnections,
            this::checkExecutionTiming
    );
    
    for (DetectionTechnique technique : techniques) {
      try {
        if (technique.detect()) {
          isDetected.set(true);
          Log.w(TAG, "Frida detectado por: " + technique.getClass().getSimpleName());
          return true;
        }
      } catch (Exception e) {
        Log.d(TAG, "Error en técnica de detección: " + e.getMessage());
      }
    }
    
    return false;
  }
  
  private interface DetectionTechnique {
    boolean detect() throws Exception;
  }
  
  private boolean checkFridaPort() {
    try {
      int[] fridaPorts = {27042, 27043, 27044};
      for (int port : fridaPorts) {
        Socket socket = new Socket();
        socket.connect(new InetSocketAddress("127.0.0.1", port), 50);
        socket.close();
        Log.w(TAG, "Puerto de Frida encontrado: " + port);
        return true;
      }
    } catch (Exception e) {
      // Puerto cerrado, continuar
    }
    return false;
  }
  
  private boolean checkFridaFiles() {
    String[] suspiciousPaths = {
            "/data/local/tmp/frida-server",
            "/data/local/tmp/re.frida.server",
            "/system/bin/frida-server",
            "/system/xbin/frida-server",
            "/sbin/frida-server",
            "/dev/frida",
            "/data/local/tmp/frida",
            "/data/local/tmp/linjector",
            "/data/local/tmp/gadget.so",
            "/data/local/tmp/libfrida-gadget.so"
    };
    
    for (String path : suspiciousPaths) {
      File file = new File(path);
      if (file.exists()) {
        Log.w(TAG, "Archivo de Frida encontrado: " + path);
        return true;
      }
    }
    return false;
  }
  
  private boolean checkFridaProcesses() {
    try {
      Process process = Runtime.getRuntime().exec(new String[]{"sh", "-c", "ps -A"});
      BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
      String line;
      
      String[] fridaKeywords = {
              "frida", "frida-server", "frida-agent", "gadget", "linjector",
              "re.frida", "frida-gadget", "libfrida"
      };
      
      while ((line = reader.readLine()) != null) {
        for (String keyword : fridaKeywords) {
          if (line.toLowerCase().contains(keyword)) {
            reader.close();
            Log.w(TAG, "Proceso de Frida encontrado: " + line);
            return true;
          }
        }
      }
      reader.close();
    } catch (Exception e) {
      Log.d(TAG, "Error checking processes: " + e.getMessage());
    }
    return false;
  }
  
  private boolean checkFridaLibraries() {
    try {
      File mapsFile = new File("/proc/self/maps");
      if (!mapsFile.exists()) return false;
      
      BufferedReader reader = new BufferedReader(new InputStreamReader(new FileInputStream(mapsFile)));
      String line;
      
      String[] fridaLibPatterns = {
              "libfrida", "frida-gadget", "gadget.so", "linjector.so"
      };
      
      while ((line = reader.readLine()) != null) {
        for (String pattern : fridaLibPatterns) {
          if (line.contains(pattern)) {
            reader.close();
            Log.w(TAG, "Librería de Frida encontrada: " + line);
            return true;
          }
        }
      }
      reader.close();
    } catch (Exception e) {
      Log.d(TAG, "Error checking libraries: " + e.getMessage());
    }
    return false;
  }
  
  private boolean checkFridaStringsInMaps() {
    try {
      File mapsFile = new File("/proc/self/maps");
      if (!mapsFile.exists()) return false;
      
      BufferedReader reader = new BufferedReader(new InputStreamReader(new FileInputStream(mapsFile)));
      String line;
      
      String[] fridaStrings = {
              "frida", "gum-js", "gumpp", "frida-gadget"
      };
      
      while ((line = reader.readLine()) != null) {
        for (String fridaString : fridaStrings) {
          if (line.toLowerCase().contains(fridaString)) {
            reader.close();
            Log.w(TAG, "String de Frida en memoria: " + line);
            return true;
          }
        }
      }
      reader.close();
    } catch (Exception e) {
      Log.d(TAG, "Error checking strings in maps: " + e.getMessage());
    }
    return false;
  }
  
  private boolean checkFridaTcpConnections() {
    try {
      Process process = Runtime.getRuntime().exec("netstat -tlnp");
      BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
      String line;
      
      while ((line = reader.readLine()) != null) {
        if (line.contains("27042") || line.contains("27043") || line.contains("frida")) {
          reader.close();
          Log.w(TAG, "Conexión TCP de Frida detectada: " + line);
          return true;
        }
      }
      reader.close();
    } catch (Exception e) {
      Log.d(TAG, "Error checking TCP connections: " + e.getMessage());
    }
    return false;
  }
  
  private boolean checkExecutionTiming() {
    try {
      long startTime = System.nanoTime();
      
      double dummy = 0;
      for (int i = 0; i < 500; i++) {
        dummy += Math.sqrt(i);
      }
      
      long endTime = System.nanoTime();
      long duration = (endTime - startTime) / 1_000_000;
      
      if (duration > 20) {
        Log.w(TAG, "Timing anomaly detected: " + duration + "ms");
        return true;
      }
      
    } catch (Exception e) {
      Log.d(TAG, "Error in timing check: " + e.getMessage());
    }
    return false;
  }
  
  private void killApp() {
    // Método drástico para cerrar la app
    android.os.Process.killProcess(android.os.Process.myPid());
    System.exit(0);
  }
}