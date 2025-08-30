package com.superking.parchisi.main

import android.os.Bundle
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import java.net.HttpURLConnection
import java.net.URL
import kotlin.concurrent.thread

class MainActivity : AppCompatActivity() {
  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)

    // Crear un TextView para mostrar el contenido
    val textView = TextView(this).apply {
      textSize = 16f
      setPadding(16, 16, 16, 16)
    }

    setContentView(textView)

    // URL del Pastebin en modo raw
    val pastebinUrl = "https://pastebin.com/raw/Vuu6j0Ac"

    // Hacer la petición en un hilo aparte
    thread {
      try {
        val url = URL(pastebinUrl)
        val connection = url.openConnection() as HttpURLConnection
        connection.requestMethod = "GET"
        connection.connect()

        val responseCode = connection.responseCode
        if (responseCode == HttpURLConnection.HTTP_OK) {
          val content = connection.inputStream.bufferedReader().use { it.readText() }
          runOnUiThread {
            textView.text = content
          }
        } else {
          runOnUiThread {
            textView.text = "Error al obtener datos: $responseCode"
          }
        }
        connection.disconnect()
      } catch (e: Exception) {
        e.printStackTrace()
        runOnUiThread {
          textView.text = "Error: ${e.message}"
        }
      }
    }
  }
}