package de.niklasmerz.cordova.biometric;

import android.app.Activity;
import android.app.KeyguardManager;
import android.content.Intent;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.support.v4.content.ContextCompat;
import android.support.v7.app.AppCompatActivity;

import com.exxbrain.android.biometric.BiometricPrompt;

import java.util.concurrent.Executor;

import javax.crypto.Cipher;

public class BiometricActivity extends AppCompatActivity {

    private static final int REQUEST_CODE_CONFIRM_DEVICE_CREDENTIALS = 2;
    private PromptInfo mPromptInfo;
    private CryptographyManager mCryptographyManager;
    private BiometricPrompt mBiometricPrompt;

    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setTitle(null);
        int layout = getResources().getIdentifier("biometric_activity", "layout", getPackageName());
        setContentView(layout);

        if (savedInstanceState != null) {
            return;
        }

        mCryptographyManager = new CryptographyManager();
        mPromptInfo = new PromptInfo.Builder(getIntent().getExtras()).build();
        final Handler handler = new Handler(Looper.getMainLooper());
        Executor executor = handler::post;
        mBiometricPrompt = new BiometricPrompt(this, executor, mAuthenticationCallback);
        try {
            authenticate();
        } catch (CryptoException e) {
            finishWithError(e);
        }
    }

    private void authenticate() throws CryptoException {
        if (mPromptInfo.getMode().equals("decrypt")) {
            authenticateToDecrypt(mPromptInfo.getSecret());
            return;
        }

        if (mPromptInfo.getMode().equals("encrypt")) {
            authenticateToEncrypt(mPromptInfo.invalidateOnEnrollment());
            return;
        }

        justAuthenticate();
    }

    private void justAuthenticate() {
        mBiometricPrompt.authenticate(createPromptInfo());
    }

    private void authenticateToEncrypt(boolean invalidateOnEnrollment) throws CryptoException {
        Cipher cipher = mCryptographyManager.getInitializedCipherForEncryption(invalidateOnEnrollment, this);
        mBiometricPrompt.authenticate(createPromptInfo(), new BiometricPrompt.CryptoObject(cipher));
    }

    private void authenticateToDecrypt(String ciphertext) throws CryptoException {
        Cipher cipher = mCryptographyManager.getInitializedCipherForDecryption(ciphertext, this);
        mBiometricPrompt.authenticate(createPromptInfo(), new BiometricPrompt.CryptoObject(cipher));
    }

    private BiometricPrompt.PromptInfo createPromptInfo() {
        BiometricPrompt.PromptInfo.Builder promptInfoBuilder = new BiometricPrompt.PromptInfo
                .Builder()
                .setTitle(mPromptInfo.getTitle())
                .setSubtitle(mPromptInfo.getSubtitle())
                .setDescription(mPromptInfo.getDescription());

        promptInfoBuilder.setNegativeButtonText(mPromptInfo.getCancelButtonTitle());

        return promptInfoBuilder.build();
    }

    private BiometricPrompt.AuthenticationCallback mAuthenticationCallback = new BiometricPrompt.AuthenticationCallback() {
        @Override
        public void onAuthenticationError(int errorCode, @NonNull CharSequence errString) {
            super.onAuthenticationError(errorCode, errString);
            onError(errorCode, errString);
        }

        @Override
        public void onAuthenticationSucceeded(@NonNull BiometricPrompt.AuthenticationResult result) {
            super.onAuthenticationSucceeded(result);
            try {
                Intent intent = null;
                BiometricPrompt.CryptoObject cryptoObject = result.getCryptoObject();

                if (mPromptInfo.getMode().equals("decrypt")) {
                    intent = getDecryptedIntent(cryptoObject);
                } else if (mPromptInfo.getMode().equals("encrypt")) {
                    intent = getEncryptIntent(cryptoObject);
                }
                
                finishWithSuccess(intent);
            } catch (CryptoException e) {
                finishWithError(e);
            }
        }

        @Override
        public void onAuthenticationFailed() {
            super.onAuthenticationFailed();
        }
    };

    private void onError(int errorCode, @NonNull CharSequence errString) {

        switch (errorCode)
        {
            case BiometricPrompt.ERROR_USER_CANCELED:
            case BiometricPrompt.ERROR_CANCELED:
                finishWithError(PluginError.BIOMETRIC_DISMISSED);
                return;
            case BiometricPrompt.ERROR_NEGATIVE_BUTTON:
                finishWithError(PluginError.BIOMETRIC_DISMISSED);
                break;
            case BiometricPrompt.ERROR_LOCKOUT:
                finishWithError(PluginError.BIOMETRIC_LOCKED_OUT.getValue(), errString.toString());
                break;
            case BiometricPrompt.ERROR_LOCKOUT_PERMANENT:
                finishWithError(PluginError.BIOMETRIC_LOCKED_OUT_PERMANENT.getValue(), errString.toString());
                break;
            default:
                finishWithError(errorCode, errString.toString());
        }
    }

    private void finishWithSuccess(Intent intent) {
        if (intent == null) {
            setResult(RESULT_OK);
        } else {
            setResult(RESULT_OK, intent);
        }
        
        finish();
    }

    private Intent getEncryptIntent(BiometricPrompt.CryptoObject cryptoObject) throws CryptoException {
        String secret = mPromptInfo.getSecret();
        String ciphertext = mCryptographyManager.encryptData(secret, cryptoObject.getCipher());

        if (ciphertext != null) {
            Intent intent = new Intent();
            intent.putExtra(Fingerprint.SECRET_EXTRA, ciphertext);
            return intent;
        }

        return null;
    }

    private Intent getDecryptedIntent(BiometricPrompt.CryptoObject cryptoObject) throws CryptoException {
        String ciphertext = mPromptInfo.getSecret();
        String secret = mCryptographyManager.decryptData(ciphertext, cryptoObject.getCipher());

        if (secret != null) {
            Intent intent = new Intent();
            intent.putExtra(Fingerprint.SECRET_EXTRA, secret);
            return intent;
        }

        return null;
    }

    private void finishWithError(CryptoException e) {
        finishWithError(e.getError().getValue(), e.getMessage());
    }

    private void finishWithError(PluginError error) {
        finishWithError(error.getValue(), error.getMessage());
    }

    private void finishWithError(int code, String message) {
        Intent data = new Intent();
        data.putExtra("code", code);
        data.putExtra("message", message);
        setResult(RESULT_CANCELED, data);
        finish();
    }
}
