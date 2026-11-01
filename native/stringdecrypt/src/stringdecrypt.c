/*
 * Native string decryptor cho Grunt (NativeStringEncryptTransformer).
 *
 * Thuật toán PHẢI khớp tuyệt đối với phần Kotlin sinh dữ liệu mã hoá lúc
 * obfuscate (xem NativeStringEncryptTransformer.kt, hàm `encrypt`) - đây là
 * bản port 1:1 sang C của Variant B (LCG keystream) trong StringEncryptTransformer.
 *
 * BUILD_SECRET là 1 số 32-bit được truyền vào lúc compile (-DBUILD_SECRET=...),
 * KHÔNG hard-code sẵn trong source này. Mỗi lần bạn build lại thư viện native
 * với 1 BUILD_SECRET khác, file .class obfuscate ra bởi Grunt với cùng secret
 * đó (cấu hình "NativeStringEncrypt.BuildSecret") mới giải mã đúng - build cũ
 * random hoặc copy nguyên file .so/.dll không tự chạy được với secret khác.
 *
 * Build thủ công (Linux ví dụ):
 *   gcc -shared -fPIC -O2 -DBUILD_SECRET=0x1A2B3C4D \
 *       -I"$JAVA_HOME/include" -I"$JAVA_HOME/include/linux" \
 *       -o libnovanative.so stringdecrypt.c
 *
 * Xem CMakeLists.txt / .github/workflows/build-native.yml để build tự động
 * cho cả Windows/Linux/macOS.
 */

#include <jni.h>
#include <stdint.h>
#include <string.h>

#ifndef BUILD_SECRET
#define BUILD_SECRET 0 /* mặc định KHÔNG an toàn - luôn override lúc build thật */
#endif

/* Hằng số build-time dùng chung với Kotlin, KHÔNG phải bí mật - chỉ để trộn bit. */
static const uint32_t GOLDEN  = 0x9E3779B9u;
static const uint32_t LCG_MUL = 1103515245u;
static const uint32_t LCG_ADD = 12345u;

/*
 * Tên hàm JNI này PHẢI khớp package/class/method mà NativeStringEncryptTransformer
 * sinh ra (mặc định: novanative.NativeBridge#decrypt0). Nếu bạn đổi tên
 * package/class trong cấu hình Grunt, phải đổi tên hàm export này tương ứng
 * (quy tắc JNI: Java_<package_>_<Class>_<method>, dấu "_" trong tên gốc
 * thành "_1").
 *
 * Chữ ký: static native String decrypt0(char[] arr, long seed, int key, int classKey);
 */
JNIEXPORT jstring JNICALL Java_novanative_NativeBridge_decrypt0(
    JNIEnv* env, jclass clazz, jcharArray arrIn, jlong seed, jint key, jint classKey
) {
    (void) clazz;
    if (arrIn == NULL) return NULL;

    jsize len = (*env)->GetArrayLength(env, arrIn);
    jchar* arr = (*env)->GetCharArrayElements(env, arrIn, NULL);
    if (arr == NULL) return NULL;

    /* classKey thực tế dùng để mã hoá luôn bị XOR với BUILD_SECRET trước -
       xem cùng công thức ở phía Kotlin (effectiveClassKey). */
    uint32_t effClassKey = (uint32_t) classKey ^ (uint32_t) BUILD_SECRET;

    uint32_t n = effClassKey ^ (uint32_t) key;
    uint64_t l = (uint64_t) seed;

    for (jsize i = 0; i < len; i++) {
        uint32_t mask = (n ^ (uint32_t)(int32_t) l) + ((uint32_t) i) * GOLDEN;
        jchar c = (jchar) (arr[i] ^ (mask & 0xFFFFu));
        arr[i] = c;
        n = n * LCG_MUL + LCG_ADD;
        l = l ^ (uint64_t) i;
    }

    jstring result = (*env)->NewString(env, arr, len);
    /* JNI_ABORT: không cần copy ngược lại mảng Java (ta không cần giữ bản rõ ở đó lâu) */
    (*env)->ReleaseCharArrayElements(env, arrIn, arr, JNI_ABORT);
    return result;
}

/*
 * Optional: JNI_OnLoad chỉ để xác nhận version, không bắt buộc nhưng giúp
 * fail sớm, rõ ràng nếu nhúng nhầm JDK quá cũ.
 */
JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* reserved) {
    (void) vm;
    (void) reserved;
    return JNI_VERSION_1_6;
}
