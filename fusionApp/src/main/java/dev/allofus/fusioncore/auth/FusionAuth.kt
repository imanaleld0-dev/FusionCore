package dev.allofus.fusioncore.auth

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.os.Build
import android.util.Log
import com.google.android.gms.auth.api.signin.GoogleSignIn
import com.googleandroid.gms.authapi.signin.GoogleSignInAccount
import com.google.android.gms.auth.api.signin.GoogleSignInClient
import com.google.android.gms.auth.api.signin.GoogleSignInOptions
import com.google.android.gms.common.api.ApiException
import com.google.android.gms.games.PlayGamesSdk
import org.json.JSONObject
import java.io.File

object FusionAuth {
    private const val TAG = "FusionAuth"
    private const val WEB_CLIENT_ID = "123627248081-4jssptbfgnk5un642tagj8iuid8gjr15.apps.googleusercontent.com" // замените
    private const val RC_SIGN_IN = 9001
    private const val TOKEN_FILE = "fusion_auth.json"
    private var googleClient: GoogleSignInClient? = null

    fun init(activity: Activity) {
        try {
            PlayGamesSdk.initialize(activity)
        } catch (e: Exception) {
            Log.w(TAG, "PlayGamesSdk init failed: $e")
        }

        val gso = GoogleSignInOptions.Builder(GoogleSignInOptions.DEFAULT_GAMES_SIGN_IN)
            .requestServerAuthCode(WEB_CLIENT_ID)
            .requestIdToken(WEB_CLIENT_ID)
            .build()
        googleClient = GoogleSignIn.getClient(activity, gso)
    }

    fun startSignIn(activity: Activity) {
        val client = googleClient ?: run {
            Log.e(TAG, "GoogleSignInClient not initialized")
            return
        }
        activity.startActivityForResult(client.signInIntent, RC_SIGN_IN)
    }

    fun handleResult(requestCode: Int, data: Intent?, activity: Activity? = null) : Boolean {
        if (requestCode != RC_SIGN_IN) return false
        val task = GoogleSignIn.getSignedInAccountFromIntent(data)
        try {
            val account = task.getResult(ApiException::class.java)
            saveAuth(account, activity)
            Log.d(TAG, "Auth saved")
        } catch (e: ApiException) {
            Log.e(TAG, "Sign-in failed: ${e.statusCode} / ${e.message}")
        }
        return true
    }

    private fun saveAuth(account: GoogleSignInAccount?, activity: Activity? = null) {
        if (account == null) return
        val idToken = account.idToken ?: ""
        val authCode = account.serverAuthCode ?: ""
        val expiry = jwtExpiry(idToken)

        val json = JSONObject().apply {
            put("idToken", idToken)
            put("connectToken", authCode)
            put("productUserId", account.id ?: "")
            put("credentialType", 12) // GOOGLE_ID_TOKEN
            put("expiresAt", expiry)
        }

        // Try to put in app external folder first
        val file = File(getStorageDir(activity), TOKEN_FILE)
        try {
            file.writeText(json.toString())
            Log.d(TAG, "Saved token to ${file.absolutePath}")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to write token file: $e")
        }

        // Optionally: start Among Us with Intent carrying the JSON (recommended)
        if (activity != null) {
            try {
                val packageName = "com.innersloth.spacemafia" // Among Us package
                val pm = activity.packageManager
                val launchIntent = pm.getLaunchIntentForPackage(packageName)
                if (launchIntent != null) {
                    launchIntent.putExtra("fusion_auth_json", json.toString())
                    // Optionally add flags if launching from another app
                    launchIntent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                    activity.startActivity(launchIntent)
                    Log.d(TAG, "Started Among Us with token via Intent")
                } else {
                    Log.w(TAG, "Launch intent for $packageName not found")
                }
            } catch (e: Exception) {
                Log.e(TAG, "Failed to start Among Us via Intent: $e")
            }
        }
    }

    fun clearAuth(activity: Activity? = null) {
        val file = File(getStorageDir(activity), TOKEN_FILE)
        if (file.exists()) file.delete()
        googleClient?.signOut()
    }

    fun hasAuth(activity: Activity? = null): Boolean {
        val file = File(getStorageDir(activity), TOKEN_FILE)
        if (!file.exists()) return false
        return try {
            val json = JSONObject(file.readText())
            val exp = json.optLong("expiresAt", 0L)
            val now = System.currentTimeMillis() / 1000
            now < exp - 60
        } catch (e: Exception) {
            false
        }
    }

    private fun jwtExpiry(jwt: String): Long {
        return try {
            val parts = jwt.split(".")
            if (parts.size < 2) return 0
            val payload = String(android.util.Base64.decode(parts[1], android.util.Base64.URL_SAFE), Charsets.UTF_8)
            JSONObject(payload).optLong("exp", 0L)
        } catch (e: Exception) {
            0L
        }
    }

    private fun getStorageDir(activity: Activity? = null): File {
        // Prefer app externalFilesDir if available, fallback to common path
        return try {
            val dir = activity?.getExternalFilesDir(null)
            if (dir != null) return File(dir, "FusionCore").apply { mkdirs() }
            // fallback to /sdcard/FusionCore
            File("/sdcard/FusionCore").apply { mkdirs() }
        } catch (e: Exception) {
            File("/sdcard/FusionCore").apply { mkdirs() }
        }
    }
}
