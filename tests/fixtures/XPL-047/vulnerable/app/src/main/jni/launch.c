#include <jni.h>
#include <stdio.h>
#include <string.h>

#define CODESIZEMAX 20

JNIEXPORT jint JNICALL Java_com_demo_Native_launch(JNIEnv *env, jobject obj, jstring jcode) {
    const char *pcode = (*env)->GetStringUTFChars(env, jcode, 0);
    char code[CODESIZEMAX];
    char label[64];

    strcpy(code, pcode);
    sprintf(label, "code=%s", pcode);
    (*env)->ReleaseStringUTFChars(env, jcode, pcode);
    return code[0] == '.';
}
