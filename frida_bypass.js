/*
 * OTP-SNIPER — Frida Bypass SSL Pinning
 * Usage :
 *   frida -U -f com.example.app -l frida_bypass.js --no-pause
 */

Java.perform(function() {
    console.log("[*] OTP-SNIPER — Frida SSL Bypass démarré");

    // === 1. Bypass TrustManager ===
    try {
        var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
        var SSLContext = Java.use('javax.net.ssl.SSLContext');

        var TrustManagerImpl = Java.registerClass({
            name: 'com.otp.sniper.TrustManager',
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: function(chain, authType) {},
                checkServerTrusted: function(chain, authType) {},
                getAcceptedIssuers: function() { return []; }
            }
        });

        var TrustManagers = [TrustManagerImpl.$new()];
        var sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, TrustManagers, null);
        console.log("[+] TrustManager bypass installé");
    } catch (e) {
        console.log("[-] TrustManager: " + e);
    }

    // === 2. Bypass OkHttp3 CertificatePinner ===
    try {
        var CertificatePinner = Java.use('okhttp3.CertificatePinner');
        CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function() {
            console.log("[+] OkHttp3 bypass");
            return;
        };
    } catch (e) {}

    // === 3. Bypass OkHttp2 ===
    try {
        var OkHttpClient = Java.use('com.squareup.okhttp.OkHttpClient');
        OkHttpClient.setCertificatePinner.implementation = function() {
            return this;
        };
    } catch (e) {}

    // === 4. Bypass TrustKit ===
    try {
        var TrustKit = Java.use('com.datatheorem.android.trustkit.pinning.OkHostnameVerifier');
        TrustKit.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation = function() {
            return true;
        };
    } catch (e) {}

    // === 5. Bypass HostnameVerifier ===
    try {
        var HostnameVerifier = Java.use('javax.net.ssl.HostnameVerifier');
        var HNV = Java.registerClass({
            name: 'com.otp.sniper.HNV',
            implements: [HostnameVerifier],
            methods: {
                verify: function(hostname, session) { return true; }
            }
        });
        console.log("[+] HostnameVerifier bypass");
    } catch (e) {}

    console.log("[*] Bypass complet — Configure ton proxy Wi-Fi sur [IP_PC]:8080");
});