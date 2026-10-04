// 1. ターゲット設定
const CONFIG = {
    targetPackage: "net.time.good.tree",

    customClasses: {
        sd: "Sd",              // アンチエミュレータ・サンドボックス検知
        sc: "SC",              // 文字列復号器
        pd: "Pd",              // ペイロード復号 & 展開
        sp: "Sp",              // APK署名ブロック修飾
        jsBridge: "b2.n",      // JavaScriptInterface
        mainActivity: "MainActivity" // メインアクティビティ
    }
};

Java.perform(function () {
    // -------------------------------------------------------------------------
    // 0. コンテキストおよび保存先ディレクトリの自動検出
    // -------------------------------------------------------------------------
    let currentPackage = CONFIG.targetPackage;
    let dumpDir = `/data/data/${currentPackage}`;

    try {
        const ActivityThread = Java.use("android.app.ActivityThread");
        const currentApplication = ActivityThread.currentApplication();
        if (currentApplication) {
            const context = currentApplication.getApplicationContext();
            currentPackage = context.getPackageName();
            dumpDir = context.getFilesDir().getAbsolutePath();
        }
    } catch (e) {
        console.warn("[-] Failed to auto-detect package name. Using fallback.");
    }

    if (!currentPackage) currentPackage = "Unknown_Package";

    console.log(`[*] Dump directory set to: ${dumpDir}`);

    function resolveClassName(shortName) {
        if (!shortName) return null;
        return shortName.includes(".") ? shortName : `${currentPackage}.${shortName}`;
    }

    function tryUse(className) {
        if (!className) return null;
        try {
            return Java.use(className);
        } catch (e) {
            return null;
        }
    }

    // -------------------------------------------------------------------------
    // 1. サンドボックス・エミュレータ検知の完全バイパス (Sd.java)
    // -------------------------------------------------------------------------
    const sdClassName = resolveClassName(CONFIG.customClasses.sd);
    const Sd = tryUse(sdClassName);
    if (Sd) {
        try {
            if (Sd.isSandboxEnvironment) {
                Sd.isSandboxEnvironment.implementation = function (context) {
                    console.log("[+] [BYPASS] Sd.isSandboxEnvironment called -> forced return FALSE");
                    return false;
                };
            }
            if (Sd.isEmulator) {
                Sd.isEmulator.implementation = function () {
                    console.log("[+] [BYPASS] Sd.isEmulator called -> forced return FALSE");
                    return false;
                };
            }
            if (Sd.isChineseEmulator) {
                Sd.isChineseEmulator.implementation = function (context) {
                    console.log("[+] [BYPASS] Sd.isChineseEmulator called -> forced return FALSE");
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
            if (Sd.hasAbnormalHardware) {
                Sd.hasAbnormalHardware.implementation = function () {
                    console.log("[+] [BYPASS] Sd.hasAbnormalHardware called -> forced return FALSE");
                    return false;
                };
            }
            if (Sd.getProp) {
                Sd.getProp.implementation = function (prop) {
                    const val = this.getProp(prop);
                    console.log(`[Sd::getProp] Checked: "${prop}" => "${val}"`);
                    return val;
                };
            }
            console.log(`[+] Hooked Anti-Sandbox/Emulator: ${sdClassName}`);
        } catch (e) {
            console.warn(`[-] Failed to hook ${sdClassName}: ${e}`);
        }
    }

    // -------------------------------------------------------------------------
    // 2. 文字列復号器のトレース (SC.java)
    // -------------------------------------------------------------------------
    const scClassName = resolveClassName(CONFIG.customClasses.sc);
    const SC = tryUse(scClassName);
    if (SC) {
        try {
            if (SC.d) {
                SC.d.implementation = function (encStr) {
                    const decStr = this.d(encStr);
                    console.log(`[STR_DEC] "${encStr}" => "${decStr}"`);
                    return decStr;
                };
                console.log(`[+] Hooked String Decryptor: ${scClassName}.d`);
            }
        } catch (e) {
            console.warn(`[-] Failed to hook ${scClassName}: ${e}`);
        }
    }

    // -------------------------------------------------------------------------
    // 3. ペイロード復号 & 署名ブロック修飾の詳細トレース (Pd.java, Sp.java)
    // -------------------------------------------------------------------------
    const pdClassName = resolveClassName(CONFIG.customClasses.pd);
    const Pd = tryUse(pdClassName);
    if (Pd) {
        try {
            if (Pd.load) {
                Pd.load.implementation = function (context) {
                    console.log("\n[+] [PAYLOAD] Pd.load(context) called! Decrypting asset payload...");
                    const decryptedBytes = this.load(context);
                    if (decryptedBytes) {
                        console.log(`[+] [PAYLOAD] Decrypted raw payload: ${decryptedBytes.length} bytes`);
                        saveBytesToFile(decryptedBytes, `${dumpDir}/dumped_payload_raw.bin`);
                    }
                    return decryptedBytes;
                };
            }
            if (Pd.k0) {
                Pd.k0.implementation = function (str) {
                    const keyBytes = this.k0(str);
                    console.log(`[+] [Pd.k0] Key generation arg: "${str}", Generated Key(Hex): ${bufToHex(keyBytes)}`);
                    return keyBytes;
                };
            }
            if (Pd.dec) {
                Pd.dec.implementation = function (context, str, bArr) {
                    console.log(`[+] [Pd.dec] Called with str: "${str}", Input size: ${bArr ? bArr.length : 0} bytes`);
                    const decBytes = this.dec(context, str, bArr);
                    console.log(`[+] [Pd.dec] Output size: ${decBytes ? decBytes.length : 0} bytes`);
                    return decBytes;
                };
            }
            if (Pd.decompress) {
                Pd.decompress.implementation = function (bArr) {
                    console.log(`[+] [Pd.decompress] Input size: ${bArr ? bArr.length : 0} bytes`);
                    const decomp = this.decompress(bArr);
                    console.log(`[+] [Pd.decompress] Output decompressed size: ${decomp ? decomp.length : 0} bytes`);
                    return decomp;
                };
            }
            console.log(`[+] Hooked Payload Loader: ${pdClassName}`);
        } catch (e) {
            console.warn(`[-] Failed to hook ${pdClassName}: ${e}`);
        }
    }

    const spClassName = resolveClassName(CONFIG.customClasses.sp);
    const Sp = tryUse(spClassName);
    if (Sp) {
        try {
            if (Sp.m0) {
                Sp.m0.implementation = function (bytesIn) {
                    console.log("\n[+] [PAYLOAD] Sp.m0 called (signing block processing)...");
                    const resultBytes = this.m0(bytesIn);
                    if (resultBytes) {
                        console.log(`[+] [PAYLOAD] Final modified APK ready: ${resultBytes.length} bytes`);
                        saveBytesToFile(resultBytes, `${dumpDir}/dumped_payload_final.apk`);
                    }
                    return resultBytes;
                };
                console.log(`[+] Hooked Signing Processor: ${spClassName}.m0`);
            }
        } catch (e) {
            console.warn(`[-] Failed to hook ${spClassName}: ${e}`);
        }
    }

    // -------------------------------------------------------------------------
    // 4. PackageInstaller 監視 & 不明アプリインストール許可バイパス (b2.i)
    // -------------------------------------------------------------------------
    try {
        const ApplicationPackageManager = Java.use("android.app.ApplicationPackageManager");
        ApplicationPackageManager.canRequestPackageInstalls.implementation = function () {
            console.log("[+] [BYPASS] canRequestPackageInstalls called -> forced return TRUE (Bypassing wait loop)");
            return true;
        };

        const PackageInstaller = Java.use("android.content.pm.PackageInstaller");
        PackageInstaller.createSession.overload('android.content.pm.PackageInstaller$SessionParams').implementation = function (params) {
            const sessionId = this.createSession(params);
            console.log(`\n[+] [INSTALLER] createSession created (ID: ${sessionId})`);
            return sessionId;
        };

        const PackageInstallerSession = Java.use("android.content.pm.PackageInstaller$Session");
        PackageInstallerSession.openWrite.overload('java.lang.String', 'long', 'long').implementation = function (name, offsetBytes, lengthBytes) {
            console.log(`[+] [INSTALLER] Session.openWrite: Name="${name}", Offset=${offsetBytes}, Length=${lengthBytes}`);
            return this.openWrite(name, offsetBytes, lengthBytes);
        };

        PackageInstallerSession.commit.implementation = function (statusReceiver) {
            console.log("[+] [INSTALLER] Session.commit() called! Silent installation initiated.");
            return this.commit(statusReceiver);
        };
        console.log("[+] Hooked PackageInstaller & unknown sources bypass");
    } catch (e) {
        console.warn("[-] Failed to hook PackageInstaller: " + e);
    }

    // -------------------------------------------------------------------------
    // 5. メインアクティビティ & 状態遷移ディスパッチの監視 (MainActivity.java)
    // -------------------------------------------------------------------------
    const mainActivityClassName = resolveClassName(CONFIG.customClasses.mainActivity);
    const MainActivity = tryUse(mainActivityClassName);
    if (MainActivity) {
        try {
            if (MainActivity.d0) {
                MainActivity.d0.implementation = function (reason) {
                    console.log(`\n[!!! STAGE TRANSITION !!!] MainActivity.d0 called with reason: "${reason}"`);
                    return this.d0(reason);
                };
            }
            if (MainActivity.launchVpn) {
                MainActivity.launchVpn.implementation = function () {
                    console.log("[+] [VPN] MainActivity.launchVpn() triggered");
                    return this.launchVpn();
                };
            }
            if (MainActivity.setInstalling) {
                MainActivity.setInstalling.implementation = function (flag) {
                    console.log(`[MainActivity] setInstalling(${flag})`);
                    return this.setInstalling(flag);
                };
            }
            console.log(`[+] Hooked MainActivity flow triggers: ${mainActivityClassName}`);
        } catch (e) {
            console.warn(`[-] Failed to hook ${mainActivityClassName}: ${e}`);
        }
    }

    // -------------------------------------------------------------------------
    // 6. 暗号処理・鍵生成の捕捉 (javax.crypto / AESキーダンプ)
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
    // 7. JavaScript ブリッジの自動フック (b2.n / 動的登録)
    // -------------------------------------------------------------------------
    const jsBridgeClassName = CONFIG.customClasses.jsBridge;
    const N = tryUse(jsBridgeClassName);
    if (N) {
        try {
            const methods = N.class.getDeclaredMethods();
            methods.forEach(function (method) {
                const methodName = method.getName();
                const overloads = N[methodName].overloads;
                overloads.forEach(function (overload) {
                    overload.implementation = function () {
                        const args = [].slice.call(arguments);
                        console.log(`\n[!!! JS_BRIDGE CALL !!!] Interface.${methodName}(${JSON.stringify(args)})`);
                        return this[methodName].apply(this, arguments);
                    };
                });
            });
            console.log(`[+] Hooked all methods of JavaScriptInterface: ${jsBridgeClassName}`);
        } catch (e) {
            console.warn(`[-] Failed to hook ${jsBridgeClassName}: ${e}`);
        }
    }

    // -------------------------------------------------------------------------
    // 8. WebView 監視 (マルチオーバーロード・JS注入・動的ブリッジ)
    // -------------------------------------------------------------------------
    try {
        const WebView = Java.use("android.webkit.WebView");

        WebView.loadUrl.overload('java.lang.String').implementation = function (url) {
            console.log(`[WebView::loadUrl] ${url}`);
            return this.loadUrl(url);
        };

        WebView.loadUrl.overload('java.lang.String', 'java.util.Map').implementation = function (url, headers) {
            console.log(`[WebView::loadUrlWithHeaders] ${url}, Headers: ${headers}`);
            return this.loadUrl(url, headers);
        };

        if (WebView.postUrl) {
            WebView.postUrl.implementation = function (url, postData) {
                try {
                    const String = Java.use("java.lang.String");
                    console.log(`[WebView::postUrl] ${url}, Data: ${String.$new(postData)}`);
                } catch (e) {
                    console.log(`[WebView::postUrl] ${url}, DataLen: ${postData ? postData.length : 0}`);
                }
                return this.postUrl(url, postData);
            };
        }

        if (WebView.evaluateJavascript) {
            WebView.evaluateJavascript.implementation = function (script, callback) {
                console.log(`[WebView::evaluateJavascript] INJECTED JS:\n${script}`);
                return this.evaluateJavascript(script, callback);
            };
        }

        WebView.addJavascriptInterface.implementation = function (obj, name) {
            const bridgedClassName = obj.$className;
            console.log(`[WebView::addJavascriptInterface] Bridged Object: ${bridgedClassName} as '${name}'`);
            hookDynamicJSBridge(bridgedClassName, name);
            return this.addJavascriptInterface(obj, name);
        };
    } catch (e) {
        console.warn("[-] Failed to hook WebView: " + e);
    }

    // -------------------------------------------------------------------------
    // 9. ネットワーク & C2 通信監視 (リクエスト・レスポンス・ヘッダー完全監視)
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

        const HttpURLConnection = Java.use("java.net.HttpURLConnection");
        HttpURLConnection.getResponseCode.implementation = function () {
            const code = this.getResponseCode();
            try {
                console.log(`[HTTP::ResponseStatus] ${this.getURL()} -> Status ${code}`);
            } catch (e) {}
            return code;
        };

        HttpURLConnection.setRequestProperty.implementation = function (key, value) {
            if (key.toLowerCase().includes("user-agent") || key.toLowerCase().includes("token") || 
                key.toLowerCase().includes("auth") || key.toLowerCase().includes("content-type")) {
                console.log(`[HTTP::Header] ${key}: ${value}`);
            }
            return this.setRequestProperty(key, value);
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
            } catch (e) {}
            return this.write(bArr, off, len);
        };
    } catch (e) {
        console.warn("[-] Failed to hook Network: " + e);
    }

    // -------------------------------------------------------------------------
    // 10. SharedPreferences の監視 (状態フラグ保存の検知)
    // -------------------------------------------------------------------------
    try {
        const EditorImpl = Java.use("android.app.SharedPreferencesImpl$EditorImpl");
        EditorImpl.putBoolean.implementation = function (key, val) {
            console.log(`[SharedPrefs::PutBoolean] Key: "${key}" = ${val}`);
            return this.putBoolean(key, val);
        };
        EditorImpl.putString.implementation = function (key, val) {
            console.log(`[SharedPrefs::PutString] Key: "${key}" = "${val}"`);
            return this.putString(key, val);
        };
    } catch (e) {}

    // -------------------------------------------------------------------------
    // 11. アプリ間連携・本体起動 Intent の監視
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
    // 12. VPN Service の構成・パラメータ監視 & establish()
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

        VpnBuilder.establish.implementation = function () {
            console.log("[+] [VPN::Establish] VpnService$Builder.establish() called! TUN interface opening.");
            return this.establish();
        };
    } catch (e) {
        console.warn("[-] Failed to hook VpnService$Builder: " + e);
    }
});

// -----------------------------------------------------------------------------
// 13. ネイティブ層: JNI Lookup の監視 (libart.so)
// -----------------------------------------------------------------------------
(function hookJNI() {
    const libart = Process.findModuleByName("libart.so");
    if (!libart) return;

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

// -----------------------------------------------------------------------------
// ヘルパー関数群
// -----------------------------------------------------------------------------
function hookDynamicJSBridge(className, interfaceName) {
    try {
        const TargetClass = Java.use(className);
        const methods = TargetClass.class.getDeclaredMethods();

        methods.forEach(function (method) {
            const methodName = method.getName();
            const overloads = TargetClass[methodName].overloads;

            overloads.forEach(function (overload) {
                overload.implementation = function () {
                    const args = [].slice.call(arguments);
                    console.log(`\n[!!! DYNAMIC JS_BRIDGE CALL !!!] ${interfaceName}.${methodName}(${JSON.stringify(args)})`);
                    return this[methodName].apply(this, arguments);
                };
            });
        });
        console.log(`[+] Dynamically hooked JSBridge target class: ${className}`);
    } catch (e) {
        console.warn(`[-] Failed dynamic hook for JSBridge (${className}): ${e}`);
    }
}

function saveBytesToFile(byteArray, filePath) {
    try {
        const File = Java.use("java.io.File");
        const FileOutputStream = Java.use("java.io.FileOutputStream");

        const file = File.$new(filePath);
        const fos = FileOutputStream.$new(file);
        fos.write(byteArray);
        fos.flush();
        fos.close();
        console.log(`[***] SAVED TO: ${filePath}\n      (Pull command: adb pull ${filePath})`);
    } catch (err) {
        console.error("[-] Error saving file: " + err);
    }
}

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
