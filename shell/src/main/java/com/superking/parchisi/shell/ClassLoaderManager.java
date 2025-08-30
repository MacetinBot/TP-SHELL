package com.superking.parchisi.shell;

public class ClassLoaderManager {
  private static ClassLoader secondaryClassLoader;
  
  public static void setSecondaryClassLoader(ClassLoader classLoader) {
    secondaryClassLoader = classLoader;
  }
  
  public static ClassLoader getSecondaryClassLoader() {
    return secondaryClassLoader;
  }
}