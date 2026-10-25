[masaudit documentation](README.md) › Compared with rnsec

# React Native coverage compared with rnsec

[rnsec](https://github.com/adnxy/rnsec) is a free React Native security scanner with 105 rules. This page
maps each of them to masaudit, so you can see what masaudit covers, what it covers in part, and what it
leaves out on purpose.

**How it was checked:** for each rnsec rule (version 1.4.0, commit `a04fff6`), a small React Native
project was written with the code that rule flags, and masaudit 0.6.0 scanned it as a banking app. The
"masaudit" column lists the rules that fired. "Partial" means some forms that rnsec flags fire and others
don't; the note names the one that doesn't. Rules about Android or iOS settings need the project's
`android/` or `ios/` folder, or an Expo `app.json`. No rnsec code or rule text is copied here.

**Totals:** 61 covered, 14 partial, 0 missed, and 30 not covered on purpose, because they flag
something that isn't a security weakness, apply to Node.js rather than React Native, or need network
data that masaudit doesn't use.

masaudit also has checks that rnsec doesn't: biometric checks that unlock no key (RN-012), crypto-js
passphrase keys (RN-013), console output in release (RN-015), Hermes turned off (RN-016), source maps in
the app (RN-017), debug tooling in release (RN-018), and native modules that run commands sent from
JavaScript (RN-020). Every finding also gets masaudit's app-type calibration and OWASP MASWE mapping.

## Storage

| rnsec rule | masaudit | Note |
|---|---|---|
| ASYNCSTORAGE_SENSITIVE_KEY | RN-001 | AsyncStorage writes under token or password keys. |
| ASYNCSTORAGE_PII_DATA | Not covered on purpose | An email or phone number in app storage is routine, not a weakness. |
| REDUX_PERSIST_NO_ENCRYPTION | RN-001 | redux-persist saving an auth slice to plain storage. |
| CLIPBOARD_SENSITIVE_DATA | XPL-012 | Secrets copied to the clipboard, including expo-clipboard. |
| INSECURE_FILE_STORAGE | Partial: XPL-044 | Plain secret files fire; writes to shared Download storage do not. |
| MMKV_NO_ENCRYPTION | RN-001 | MMKV instance without encryptionKey storing a token. |
| MMKV_UNENCRYPTED_SENSITIVE_DATA | RN-001, XPL-011 | Unencrypted MMKV fires RN-001; a hardcoded MMKV key fires XPL-011. |
| UNENCRYPTED_REALM_DATABASE | XPL-031 | Unencrypted Realm schema with password or token fields. |
| UNENCRYPTED_SQLITE_DATABASE | XPL-031 | Plain SQLite tables with password or token columns. |
| SQLITE_QUERY_INJECTION | RN-011 | SQL built by string joins in RN SQLite libraries. |
| EXPO_SECURE_STORE_WEAK_OPTIONS | IOS-008 | expo-secure-store Always accessibility classes; needs an iOS target. |

## Network

| rnsec rule | masaudit | Note |
|---|---|---|
| INSECURE_HTTP_URL | XPL-009 | Plain-HTTP URLs in fetch, axios and template literals. |
| NO_REQUEST_TIMEOUT | Not covered on purpose | A missing request timeout is a reliability issue, not a security weakness. |
| WEAK_TLS_CONFIGURATION | Not covered on purpose | These Node TLS options do not exist in the React Native runtime. |
| INSECURE_WEBSOCKET | XPL-009 | ws:// URLs in WebSocket and socket.io. |
| HARDCODED_IP_ADDRESS | Not covered on purpose | A public IP address is not a weakness; HTTP and staging hosts have other rules. |
| CERT_PINNING_DISABLED | RN-004 | Pinning library switched off; Node-only options skipped on purpose. |
| TLS_VALIDATION_DISABLED_ENV | Not covered on purpose | Node-only TLS switches have no effect in Hermes or JavaScriptCore. |

## Auth

| rnsec rule | masaudit | Note |
|---|---|---|
| JWT_NO_EXPIRY_CHECK | Not covered on purpose | Token expiry is enforced by the server; the check is a per-file word heuristic. |
| TEXT_INPUT_NO_SECURE | XPL-033 | Password TextInput without secureTextEntry. |
| OAUTH_TOKEN_IN_URL | Not covered on purpose | No MASWE weakness, and signed links and public keys make it too noisy. |
| IMPROPER_BIOMETRIC_FALLBACK | Partial: XPL-043 | Hardcoded PIN fires; PIN in AsyncStorage does not. XPL-018 flags passcode fallback. |
| MISSING_SESSION_TIMEOUT | Not covered on purpose | Session lifetime is a server setting; the check looks for missing words. |
| JWT_INSECURE_SIGNING | XPL-003 | Literal JWT signing secrets. |
| OAUTH_INSECURE_FLOW | XPL-037 | Implicit flow or PKCE turned off. |
| EXPO_AUTH_SESSION_NO_PKCE | XPL-037 | expo-auth-session with PKCE turned off. |

## Secrets

| rnsec rule | masaudit | Note |
|---|---|---|
| API_KEY_EXPOSED | Partial: XPL-001, XPL-002 | Provider keys in code and .env; keys in bundled .json files missed. |
| HARDCODED_SECRETS | Partial: XPL-003 | Secret-named literals of 16+ characters; shorter passwords missed. |
| BUNDLED_ENV_SECRET | RN-002 | Secrets read from react-native-config, EXPO_PUBLIC_ or @env. |
| ENV_FILE_COMMITTED | RN-002 | Reported only when the .env file is bundled into the app. |
| COMMITTED_CREDENTIAL_FILE | Partial: CI-006 | Keystores and .p12 files; service-account JSON missed. |
| HARDCODED_BASIC_AUTH_CREDENTIALS | XPL-003 | user:password in URLs and Basic auth strings. |

## Crypto

| rnsec rule | masaudit | Note |
|---|---|---|
| WEAK_HASH_ALGORITHM | Partial: XPL-007 | crypto-js MD5/SHA-1 fires; expo-crypto SHA-1 does not. |
| HARDCODED_ENCRYPTION_KEY | Partial: XPL-011, XPL-006, XPL-016 | Inline keys, fixed IVs and salts fire; key constants passed through parse() missed. |
| WEAK_CIPHER_OR_MODE | XPL-004, XPL-013, XPL-006 | ECB mode, DES, 3DES, RC4 and fixed IVs. |
| CUSTOM_CRYPTO_IMPLEMENTATION | Not covered on purpose | Judges functions by name only; most encrypt() helpers wrap a real library. |
| INSECURE_RANDOM | XPL-008, XPL-045 | Math.random or Date.now used for tokens and nonces. |

## Logging

| rnsec rule | masaudit | Note |
|---|---|---|
| SENSITIVE_LOGGING | XPL-010 | Tokens and passwords passed to console calls. |
| SENSITIVE_DATA_IN_ERROR_MESSAGES | Not covered on purpose | Logging or showing an error is not a weakness without sensitive data in it. |

## React Native

| rnsec rule | masaudit | Note |
|---|---|---|
| JAVASCRIPT_ENABLED_BRIDGE | Not covered on purpose | Calling your own native module is not a trust boundary; RN-020 checks native code. |
| INSECURE_DEEPLINK_HANDLER | RN-009 | Deep-link URLs reaching fetch, openURL or navigation params; path routing skipped. |
| INSECURE_LINKING_OPEN | Partial: RN-009, RN-008 | Deep-link and WebView-message URLs fire; React Navigation params do not. |
| EVAL_USAGE | RN-010 | eval and new Function on runtime strings. |
| OBFUSCATED_EVAL_EXECUTION | RN-010 | eval of base64-decoded text, flagged as possibly malicious. |
| INSECURE_DESERIALIZATION | RN-010 | Same eval shape as EVAL_USAGE. |
| SENSITIVE_NAVIGATION_PARAMS | Not covered on purpose | Navigation params stay in memory unless the app persists navigation state. |
| PUSH_NOTIFICATION_SENSITIVE_DATA | Not covered on purpose | Duplicates the logging and plain-storage rules on a narrower path. |
| SCREENSHOT_PROTECTION_MISSING | AND-045, IOS-030 | No screenshot or app-switcher protection in the app. |
| ROOT_JAILBREAK_DETECTION_ABSENT | XPL-021 | No root or jailbreak detection in a high-risk app. |
| MISSING_RUNTIME_INTEGRITY_CHECKS | AND-048, IOS-028 | No Play Integrity or App Attest integration. |
| THIRD_PARTY_SDK_RISK | Not covered on purpose | Having an analytics or attribution SDK is not itself a weakness. |
| UNSAFE_DANGEROUSLY_SET_INNER_HTML | XPL-046 | dangerouslySetInnerHTML and WebView HTML built from variables. |

## Debug

| rnsec rule | masaudit | Note |
|---|---|---|
| TEST_CREDENTIALS_IN_CODE | Not covered on purpose | Placeholder test values are not working credentials. |
| DEBUG_ENDPOINTS_EXPOSED | XPL-036 | Debug endpoint URLs in shipping code. |
| REDUX_DEVTOOLS_ENABLED | Not covered on purpose | The Redux DevTools browser extension does not exist in a release RN bundle. |
| NETWORK_LOGGER_IN_PRODUCTION | RN-003 | Axios interceptors logging bodies; skipped when release strips console. |

## WebView

| rnsec rule | masaudit | Note |
|---|---|---|
| WEBVIEW_JAVASCRIPT_INJECTION | Partial: RN-007 | Route-param and typed URLs fire; URLs passed as component props do not. |
| WEBVIEW_FILE_ACCESS | RN-005 | WebView file and universal file-URL access. |
| WEBVIEW_DOM_STORAGE_ENABLED | Not covered on purpose | DOM storage is the WebView default and most sites need it. |
| WEBVIEW_GEOLOCATION_ENABLED | Not covered on purpose | Geolocation is still gated by the operating system permission prompt. |
| WEBVIEW_MIXED_CONTENT | AND-011 | WebView mixedContentMode always; needs an Android target. |
| WEBVIEW_UNVALIDATED_NAVIGATION | Partial: RN-007 | Route-param URLs fire even with onNavigationStateChange; prop URLs missed. |
| WEBVIEW_POSTMESSAGE_NO_ORIGIN_CHECK | RN-008 | onMessage without an origin check; variables in injected scripts. |
| WEBVIEW_CACHING_ENABLED | Not covered on purpose | Caching is the WebView default; auth-page caching is set by server headers. |
| WEBVIEW_ORIGIN_WHITELIST_WILDCARD | RN-006 | originWhitelist ['*'] on remote or variable sources. |
| MISSING_SECURITY_HEADERS | Not covered on purpose | CSP and frame headers come from the page's server, not the app. |
| INSECURE_WEBVIEW | RN-006 | Same wildcard case as WEBVIEW_ORIGIN_WHITELIST_WILDCARD. |

## Android

| rnsec rule | masaudit | Note |
|---|---|---|
| ANDROID_DEBUGGABLE_ENABLED | AND-002 | debuggable true in the Android manifest. |
| ANDROID_BACKUP_ALLOWED | AND-021 | Backup on, or left at its default, with no exclusion rules. |
| ANDROID_EXPORTED_COMPONENT | AND-015 | Exported components without a permission. |
| ANDROID_INTENT_FILTER_PERMISSIVE | Not covered on purpose | View and share intent filters are normal; exported components have other rules. |
| ANDROID_UNPROTECTED_RECEIVER | AND-015 | Exported receivers without a permission. |
| ANDROID_CONTENT_PROVIDER_NO_PERMISSION | AND-015 | Exported providers without a permission. |
| INSECURE_KEYSTORE_USAGE | XPL-004 | Keystore AES keys allowing ECB mode. |
| EXCESSIVE_PERMISSIONS | AND-033, AND-072 | Sensitive and fraud-relevant permissions. |
| ANDROID_TASK_AFFINITY_VULNERABILITY | Not covered on purpose | A custom task affinity in the victim app does not enable StrandHogg. |
| ANDROID_WEBVIEW_DEBUG_ENABLED | AND-013, IOS-014 | WebView debugging on in release, native call or webviewDebuggingEnabled prop. |
| ANDROID_MISSING_NETWORK_SECURITY_CONFIG | Not covered on purpose | No network security config is the secure default on modern target SDKs. |
| ANDROID_CLEARTEXT_ENABLED | AND-001 | usesCleartextTraffic true. |
| ANDROID_NETWORK_SECURITY_CONFIG_CLEARTEXT | AND-001, AND-035 | Cleartext allowed in base or domain network config. |
| ANDROID_USER_CA_TRUSTED | AND-003 | User-installed CAs trusted in release. |
| ANDROID_SIGNING_CREDENTIALS_HARDCODED | Partial: CI-006 | Passwords in gradle.properties fire; literal build.gradle passwords alone do not. |

## iOS

| rnsec rule | masaudit | Note |
|---|---|---|
| IOS_ATS_DISABLED | IOS-001 | NSAllowsArbitraryLoads turned on. |
| IOS_USAGE_DESCRIPTIONS_MISSING | Partial: IOS-038 | Placeholder purpose strings fire; short ones and missing Always key do not. |
| IOS_BACKGROUND_MODES_UNNECESSARY | Not covered on purpose | Listing background modes is not a weakness without evidence of misuse. |
| IOS_UNIVERSAL_LINKS_MISCONFIGURED | Not covered on purpose | Wildcard applinks are supported by Apple and still verified per domain. |
| IOS_CUSTOM_URL_SCHEME_UNPROTECTED | Not covered on purpose | A custom URL scheme alone is not a weakness; handler validation is RN-009. |
| IOS_KEYCHAIN_ACCESS_GROUP_INSECURE | Not covered on purpose | Keychain access groups are limited to the same signing team. |
| IOS_DATA_PROTECTION_MISSING | IOS-010 | Data Protection entitlement set to none. |
| IOS_ATS_EXCEPTION_TOO_PERMISSIVE | IOS-001, IOS-002, IOS-003 | Web-content ATS bypass, HTTP exception domains, old TLS. |
| INSECURE_KEYCHAIN_USAGE | IOS-008 | Always Keychain classes from JS and native code. |
| IOS_INSECURE_PASTEBOARD_USAGE | IOS-020 | Secrets copied to UIPasteboard in native code. |
| IOS_MISSING_APP_SNAPSHOT_PROTECTION | IOS-030 | No app-switcher snapshot protection. |
| IOS_FILE_SHARING_ENABLED | Partial: IOS-034 | Fires only when sensitive files are written to shared Documents. |

## Expo/EAS

| rnsec rule | masaudit | Note |
|---|---|---|
| EXPO_CONFIG_INSECURE_SETTINGS | Partial: AND-021, AND-001, IOS-001 | Backup, cleartext and ATS settings in app.json; file sharing alone missed. |
| EXPO_SENSITIVE_CONFIG_EXPOSED | RN-002 | Secrets in Expo extra or plugin options. |
| EAS_JSON_SECRET_IN_ENV | RN-002 | Secrets in eas.json build env. |
| EXPO_INSECURE_PERMISSIONS | AND-033 | Sensitive permissions in Expo config. |
| EXPO_UPDATES_INSECURE_URL | RN-014 | Update manifest fetched over plain HTTP. |
| EXPO_UPDATES_NO_CODE_SIGNING | RN-014 | expo-updates without code signing. |

## Supply chain

| rnsec rule | masaudit | Note |
|---|---|---|
| SUSPICIOUS_LIFECYCLE_SCRIPT | Not covered on purpose | Install scripts are common and legitimate; malware review needs dependency tooling. |
| NPM_VULNERABLE_DEPENDENCY | Not covered on purpose | Needs network vulnerability data; masaudit is offline and static. |
| DEPRECATED_NPM_PACKAGE | Not covered on purpose | A short list of mostly Node packages; deprecation is not a weakness. |
| DEPENDENCY_NONREGISTRY_SOURCE | RN-019 | Git, wildcard, latest and http tarball dependencies; https tarballs missed. |
| NPM_REGISTRY_CONFIG_INSECURE | RN-019 | Insecure .npmrc and .yarnrc.yml settings and committed tokens. |
