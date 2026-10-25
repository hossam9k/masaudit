#include <jni.h>
#include <string.h>

#define PREF_KEY            "vendor_settings"
#define FILE_NAME_PRIVATE_KEY "privateKey.pem"
#define CACHE_KEY           "cacheEntry"
#define API_KEY_HEADER      "X-Api-Key"

JNIEXPORT jint JNICALL Java_com_demo_Vendor_access(JNIEnv *env, jobject obj, jstring jkey) {
    return 0;
}
