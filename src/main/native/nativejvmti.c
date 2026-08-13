/*
 * NativeGetClassFileBytes.c — JVMTI 原生模块
 *
 * 目标：解决 JMG 混淆载荷（Suo5 等激进 ASM 处理）retransform 失败的 dump 问题。
 *
 * 原理：JVMTI 的 GetClassFileBytes() 直接读取 JVM 内部保存的类字节码，
 *       不经过 retransform 校验——即使 JVM 拒绝 retransformClasses，这里仍能取到原始字节码。
 *
 * 用法（Java 侧）：
 *   System.load("/path/to/libnativejvmti.dylib");
 *   NativeGetClassFileBytes.init(jvmtiAgent 加载时的环境);  // 由 agent 初始化
 *   byte[] bytes = NativeGetClassFileBytes.getClassBytes(Class cls); // 对任意已加载类取字节码
 *
 * 限制：需要在目标 JVM 内以 native agent 方式加载（attach 时加载 .dylib），
 *       这是 Java 标准 API 之外的能力，JDK 9+ 模块系统不影响 JVMTI。
 */
#include <jvmti.h>
#include <jni.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

static jvmtiEnv *g_jvmti = NULL;

JNIEXPORT jint JNICALL Agent_OnLoad(JavaVM *vm, char *options, void *reserved) {
    jvmtiEnv *jvmti = NULL;
    jint res = (*vm)->GetEnv(vm, (void **)&jvmti, JVMTI_VERSION_1_2);
    if (res != JNI_OK || jvmti == NULL) {
        fprintf(stderr, "[native] GetEnv failed: %d\n", res);
        return JNI_ERR;
    }
    g_jvmti = jvmti;
    /* 能力：GetClassFileBytes 需要 can_get_bytecodes */
    jvmtiCapabilities caps;
    memset(&caps, 0, sizeof(caps));
    caps.can_get_bytecodes = 1;
    (*jvmti)->AddCapabilities(jvmti, &caps);
    fprintf(stderr, "[native] JVMTI module loaded (GetClassFileBytes ready)\n");
    return JNI_OK;
}

JNIEXPORT void JNICALL Agent_OnUnload(JavaVM *vm) {
    g_jvmti = NULL;
}

/* Java 侧调用：NativeGetClassFileBytes.getClassBytes(Class cls) → byte[] */
JNIEXPORT jbyteArray JNICALL Java_com_memshellauditor_native_NativeGetClassFileBytes_getClassBytes(
        JNIEnv *env, jclass clazz, jclass target) {
    if (g_jvmti == NULL || target == NULL) return NULL;

    jbyteArray result = NULL;
    jclass nativeClass = (*env)->FindClass(env, "java/lang/Class");
    if (nativeClass == NULL) return NULL;

    jfieldID nameField = (*env)->GetFieldID(env, nativeClass, "name", "Ljava/lang/String;");
    if (nameField == NULL) return NULL;
    jstring nameStr = (jstring)(*env)->GetObjectField(env, target, nameField);
    if (nameStr == NULL) return NULL;
    const char *name = (*env)->GetStringUTFChars(env, nameStr, NULL);

    /* GetClassFileBytes 需要 class 的 jclass */
    jbyte *bytes = NULL;
    jint len = 0;
    jvmtiError err = (*g_jvmti)->GetClassFileBytes(g_jvmti, target, &bytes, &len);
    if (err == JVMTI_ERROR_NONE && bytes != NULL && len > 0) {
        result = (*env)->NewByteArray(env, len);
        if (result != NULL) {
            (*env)->SetByteArrayRegion(env, result, 0, len, bytes);
        }
        (*g_jvmti)->Deallocate(g_jvmti, bytes);
    } else {
        fprintf(stderr, "[native] GetClassFileBytes failed for %s: %d\n",
                name ? name : "?", err);
    }
    (*env)->ReleaseStringUTFChars(env, nameStr, name);
    return result;
}
