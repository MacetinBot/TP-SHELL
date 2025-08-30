package com.superking.parchisi.shell.utils;

import android.content.Context;
import android.util.Base64;
import android.util.Log;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class KeyGeneratorUtil {
  private final List<KeyFactorProvider> providers;
  private static final String TAG = "KeyGeneratorUtil";
  
  public KeyGeneratorUtil() {
    providers = new ArrayList<>();
    providers.add(new FridaDetectionProvider());
    providers.add(new EmulatorDetectionProvider());
    providers.add(new SignatureHashProvider());
    providers.add(new SecurityProvider());
    providers.add(new NetworkProvider());
    providers.add(new PackageNameProvider());
  }
  
  public SecretKey generateSymmetricKey(Context context) throws Exception {
    StringBuilder combinedFactors = new StringBuilder();
    
    for (KeyFactorProvider provider : providers) {
      String factor = provider.getFactor(context);
      
      Log.d(TAG, provider.getClass().getSimpleName() + " -> " + factor);
      combinedFactors.append(factor);
    }
    
    Log.d(TAG, "Combined Factors: " + combinedFactors.toString());
    
    MessageDigest md = MessageDigest.getInstance("SHA-256");
    byte[] keyBytes = md.digest(combinedFactors.toString().getBytes(StandardCharsets.UTF_8));
    
    String finalKeyHash = Base64.encodeToString(keyBytes, Base64.NO_WRAP);
    Log.d(TAG, "Generated Symmetric Key (Base64): " + finalKeyHash);
    
    return new SecretKeySpec(keyBytes, "AES");
  }
  
  public void addProvider(KeyFactorProvider provider) {
    providers.add(provider);
  }
}