#include <jni.h>
#include <string.h>

#define VENDORKEY   "olsdfgad;lh"
#define CODESIZEMAX 20

JNIEXPORT jint JNICALL Java_com_demo_Vendor_access(JNIEnv *env, jobject obj, jstring jkey) {
    const char *key = (*env)->GetStringUTFChars(env, jkey, 0);
    return strncmp(VENDORKEY, key, strlen(VENDORKEY)) ? 0 : 1;
}
