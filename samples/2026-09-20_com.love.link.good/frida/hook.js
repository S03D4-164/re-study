Java.perform(function () {

    // -------------------------------------------------------------------------
    // 1. サンドボックス・エミュレータ検知の完全無効化
    // -------------------------------------------------------------------------
    try {
        const Sd = Java.use("com.love.link.good.Sd");
        
        Sd.isSandboxEnvironment.implementation = function (context) {
            console.log("[+] [BYPASS] Sd.isSandboxEnvironment called -> forced return FALSE");
            return false;
        };

        if (Sd.isEmulator) {
            Sd.isEmulator.implementation = function () {
                console.log("[+] [BYPASS] Sd.isEmulator called -> forced return FALSE");
                return false;
            };
        }
        if (Sd.isGoogleSandbox) {
            Sd.isGoogleSandbox.implementation = function (ctx) {
                console.log("[+] [BYPASS] Sd.isGoogleSandbox called -> forced return FALSE");
                return false;
            };
        }
        if (Sd.isTestEnvironment) {
            Sd.isTestEnvironment.implementation = function (ctx) {
                console.log("[+] [BYPASS] Sd.isTestEnvironment called -> forced return FALSE");
                return false;
            };
        }
    } catch (e) {
        console.warn("[-] Failed to hook Sd: " + e);
    }

    // -------------------------------------------------------------------------
    // 2. 文字列復号器 (SC.d) のトレース
    // -------------------------------------------------------------------------
    try {
        const SC = Java.use("com.love.link.good.SC");
        SC.d.implementation = function (encStr) {
            const decStr = this.d(encStr);
            console.log(`[STR_DEC] "${encStr}" => "${decStr}"`);
            return decStr;
        };
    } catch (e) {
        console.warn("[-] Failed to hook SC.d: " + e);
    }

    // -------------------------------------------------------------------------
    // 3. 復号された本命APKペイロードの自動ダンプ
    // -------------------------------------------------------------------------
    try {
        const Pd = Java.use("com.love.link.good.Pd");
        Pd.load.implementation = function (context) {
            console.log("[+] [PAYLOAD] Pd.load(context) called! Decrypting asset payload...");
            const decryptedBytes = this.load(context);
            if (decryptedBytes) {
                console.log(`[+] [PAYLOAD] Decrypted raw payload: ${decryptedBytes.length} bytes`);
                saveBytesToFile(decryptedBytes, "/data/data/com.love.link.good/dumped_payload_raw.bin");
            }
            return decryptedBytes;
        };

        const Sp = Java.use("com.love.link.good.Sp");
        Sp.m0.implementation = function (bytesIn) {
            console.log("[+] [PAYLOAD] Sp.m0 called (signing block processing)...");
            const resultBytes = this.m0(bytesIn);
            if (resultBytes) {
                console.log(`[+] [PAYLOAD] Final modified APK ready: ${resultBytes.length} bytes`);
                saveBytesToFile(resultBytes, "/data/data/com.love.link.good/dumped_payload_final.apk");
            }
            return resultBytes;
        };
    } catch (e) {
        console.warn("[-] Failed to hook Pd/Sp: " + e);
    }

    // -------------------------------------------------------------------------
    // 4. 暗号処理・鍵生成の捕捉 (javax.crypto / AESキーダンプ) [NEW]
    // -------------------------------------------------------------------------
    try {
        const Cipher = Java.use("javax.crypto.Cipher");
        Cipher.doFinal.overload('[B').implementation = function (input) {
            const result = this.doFinal(input);
            const algo = this.getAlgorithm();
            console.log(`[Crypto::Cipher] doFinal executed (Algorithm: ${algo})`);
            return result;
        };

        const SecretKeySpec = Java.use("javax.crypto.spec.SecretKeySpec");
        SecretKeySpec.$init.overload('[B', 'java.lang.String').implementation = function (key, algo) {
            console.log(`[Crypto::Key] SecretKeySpec Created! Algo: ${algo}, Key(Hex): ${bufToHex(key)}`);
            return this.$init(key, algo);
        };
    } catch (e) {
        console.warn("[-] Failed to hook Crypto APIs: " + e);
    }

    // -------------------------------------------------------------------------
    // 5. ネイティブライブラリ動的ロード監視 (System.loadLibrary) [NEW]
    // -------------------------------------------------------------------------
    try {
        const System = Java.use("java.lang.System");
        System.loadLibrary.implementation = function (libname) {
            console.log(`[+] [NativeLib] System.loadLibrary: ${libname}`);
            return this.loadLibrary(libname);
        };
        System.load.implementation = function (filename) {
            console.log(`[+] [NativeLib] System.load: ${filename}`);
            return this.load(filename);
        };
    } catch (e) {
        console.warn("[-] Failed to hook System.load: " + e);
    }

    // -------------------------------------------------------------------------
    // 6. JavaScript ブリッジ (b2.n / 'Android') の全自動フック
    // -------------------------------------------------------------------------
    try {
        const N = Java.use("b2.n");
        const methods = N.class.getDeclaredMethods();
        
        methods.forEach(function (method) {
            const methodName = method.getName();
            const overloads = N[methodName].overloads;
            
            overloads.forEach(function (overload) {
                overload.implementation = function () {
                    const args = [].slice.call(arguments);
                    console.log(`\n[!!! JS_BRIDGE CALL !!!] Android.${methodName}(${JSON.stringify(args)})`);
                    return this[methodName].apply(this, arguments);
                };
            });
        });
        console.log("[+] Hooked all methods of JavaScriptInterface: b2.n");
    } catch (e) {
        console.warn("[-] Failed to hook b2.n: " + e);
    }

    // -------------------------------------------------------------------------
    // 7. WebView 監視 (ロードURL・JS注入・インターフェース登録)
    // -------------------------------------------------------------------------
    try {
        const WebView = Java.use("android.webkit.WebView");

        WebView.loadUrl.overload('java.lang.String').implementation = function (url) {
            console.log(`[WebView::loadUrl] ${url}`);
            return this.loadUrl(url);
        };

        if (WebView.evaluateJavascript) {
            WebView.evaluateJavascript.implementation = function (script, callback) {
                console.log(`[WebView::evaluateJavascript] INJECTED JS:\n${script}`);
                return this.evaluateJavascript(script, callback);
            };
        }

        WebView.addJavascriptInterface.implementation = function (obj, name) {
            console.log(`[WebView::addJavascriptInterface] Bridged Object: ${obj.$className} as '${name}'`);
            return this.addJavascriptInterface(obj, name);
        };
    } catch (e) {
        console.warn("[-] Failed to hook WebView: " + e);
    }

    // -------------------------------------------------------------------------
    // 8. ネットワーク通信監視 (接続先 & 安全なPOST送信データのキャプチャ) [FIXED]
    // -------------------------------------------------------------------------
    try {
        const URL = Java.use("java.net.URL");
        URL.openConnection.overload().implementation = function () {
            const conn = this.openConnection();
            const urlStr = this.toString();
            if (!urlStr.includes("schema.org") && !urlStr.includes("google.com/search")) {
                console.log(`[HTTP::Connect] -> ${urlStr}`);
            }
            return conn;
        };

        const OutputStream = Java.use("java.io.OutputStream");
        OutputStream.write.overload('[B', 'int', 'int').implementation = function (bArr, off, len) {
            try {
                const String = Java.use("java.lang.String");
                const slice = bArr.slice(off, off + len);
                const sentData = String.$new(slice, "UTF-8");
                if (sentData.startsWith("{") || sentData.includes("pkg") || sentData.includes("token") || sentData.includes("account")) {
                    console.log(`[HTTP::POST_DATA] >>> ${sentData}`);
                }
            } catch (e) {
                // バイナリデータ等の文字列化失敗時はクラッシュさせずに無視
            }
            return this.write(bArr, off, len);
        };
    } catch (e) {
        console.warn("[-] Failed to hook Network: " + e);
    }

    // -------------------------------------------------------------------------
    // 9. アプリ間連携・本体起動 Intent の監視
    // -------------------------------------------------------------------------
    try {
        const Activity = Java.use("android.app.Activity");
        Activity.startActivity.overload('android.content.Intent').implementation = function (intent) {
            logIntent("startActivity", intent);
            return this.startActivity(intent);
        };

        const ContextWrapper = Java.use("android.content.ContextWrapper");
        ContextWrapper.startService.implementation = function (intent) {
            logIntent("startService", intent);
            return this.startService(intent);
        };
    } catch (e) {
        console.warn("[-] Failed to hook Intent launchers: " + e);
    }

    // -------------------------------------------------------------------------
    // 10. VPN Service (Bv) の構成・パラメータ監視
    // -------------------------------------------------------------------------
    try {
        const VpnBuilder = Java.use("android.net.VpnService$Builder");
        
        VpnBuilder.addAddress.overload('java.lang.String', 'int').implementation = function (addr, prefix) {
            console.log(`[VPN::Config] addAddress: ${addr}/${prefix}`);
            return this.addAddress(addr, prefix);
        };
        
        VpnBuilder.addRoute.overload('java.lang.String', 'int').implementation = function (addr, prefix) {
            console.log(`[VPN::Config] addRoute: ${addr}/${prefix}`);
            return this.addRoute(addr, prefix);
        };
        
        VpnBuilder.addDnsServer.overload('java.lang.String').implementation = function (dns) {
            console.log(`[VPN::Config] addDnsServer: ${dns}`);
            return this.addDnsServer(dns);
        };
    } catch (e) {
        console.warn("[-] Failed to hook VpnService$Builder: " + e);
    }
});

// -----------------------------------------------------------------------------
// 11. ネイティブ層: JNI Lookup の監視 (libart.so)
// -----------------------------------------------------------------------------
(function hookJNI() {
    const libart = Process.findModuleByName("libart.so");
    if (!libart) return;

    // FindClass
    const findClass = libart.findExportByName("_ZN3art3JNI9FindClassEP7_JNIEnvPKc") 
                   || libart.findExportByName("FindClass");
    if (findClass) {
        Interceptor.attach(findClass, {
            onEnter: function (args) {
                try {
                    const clsName = args[1].readCString();
                    if (clsName && !clsName.startsWith("java/") && !clsName.startsWith("android/")) {
                        console.log(`[JNI::FindClass] ${clsName}`);
                    }
                } catch (e) {}
            }
        });
    }

    // GetMethodID
    const getMethodID = libart.findExportByName("_ZN3art3JNI11GetMethodIDEP7_JNIEnvP7_jclassPKcS6_") 
                     || libart.findExportByName("GetMethodID");
    if (getMethodID) {
        Interceptor.attach(getMethodID, {
            onEnter: function (args) {
                try {
                    const methodName = args[2].readCString();
                    const sig = args[3].readCString();
                    console.log(`[JNI::GetMethodID] -> ${methodName} ${sig}`);
                } catch (e) {}
            }
        });
    }
})();

// ヘルパー: ファイル保存
function saveBytesToFile(byteArray, filePath) {
    try {
        const File = Java.use("java.io.File");
        const FileOutputStream = Java.use("java.io.FileOutputStream");
        
        const file = File.$new(filePath);
        const fos = FileOutputStream.$new(file);
        fos.write(byteArray);
        fos.flush();
        fos.close();
        console.log(`[***] SAVED TO: ${filePath} (Pull: adb pull ${filePath})`);
    } catch (err) {
        console.error("[-] Error saving file: " + err);
    }
}

// ヘルパー: Intent ロギング
function logIntent(type, intent) {
    if (!intent) return;
    const component = intent.getComponent();
    const action = intent.getAction();
    const compName = component ? component.flattenToString() : "none";
    
    console.log(`\n[Intent::${type}] Action: ${action}, Component: ${compName}`);
    const extras = intent.getExtras();
    if (extras) {
        const keys = extras.keySet().toArray();
        for (let i = 0; i < keys.length; i++) {
            const k = keys[i];
            console.log(`    -> Extra [${k}] = ${extras.get(k)}`);
        }
    }
}

// ヘルパー: Byte配列をHex文字列に変換
function bufToHex(bytes) {
    if (!bytes) return "";
    var hex = [];
    for (var i = 0; i < bytes.length; i++) {
        var b = (bytes[i] < 0) ? bytes[i] + 256 : bytes[i];
        hex.push((b >>> 4).toString(16));
        hex.push((b & 0xF).toString(16));
    }
    return hex.join('');
}
