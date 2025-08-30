package com.superking.parchisi.shell.utils;

import android.annotation.SuppressLint;
import android.content.Context;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import androidx.annotation.RequiresPermission;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;

public class NetworkProvider implements KeyFactorProvider {
  
  @RequiresPermission(android.Manifest.permission.ACCESS_NETWORK_STATE)
  private boolean isNetworkAvailable(Context context) {
    ConnectivityManager connectivityManager =
            (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
    
    if (connectivityManager == null) return false;
    
    Network network = connectivityManager.getActiveNetwork();
    if (network == null) return false;
    
    NetworkCapabilities capabilities = connectivityManager.getNetworkCapabilities(network);
    return capabilities != null &&
            capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET);
  }
  
  private boolean hasInternetAccess() {
    try {
      HttpURLConnection urlConnection = (HttpURLConnection)
              (new URL("https://clients3.google.com/generate_204").openConnection());
      urlConnection.setRequestProperty("User-Agent", "Android");
      urlConnection.setRequestProperty("Connection", "close");
      urlConnection.setConnectTimeout(3000);
      urlConnection.connect();
      return (urlConnection.getResponseCode() == 204 && urlConnection.getContentLength() == 0);
    } catch (IOException e) {
      return false;
    }
  }
  
  @Override
  @SuppressLint("MissingPermission")
  public String getFactor(Context context) throws Exception {
    boolean isConnected = isNetworkAvailable(context) && hasInternetAccess();
    return Boolean.toString(isConnected);
  }
}