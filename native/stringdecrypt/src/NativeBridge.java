package novanative;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;

/**
 * Loader + bridge sang thư viện native giải mã chuỗi.
 *
 * Class này được Grunt COMPILE SẴN (javac, không phải sinh bytecode bằng ASM)
 * rồi nhúng nguyên văn .class này vào project Grunt dưới dạng resource
 * (src/main/resources/native/NativeBridge.class). Lúc obfuscate,
 * NativeStringEncryptTransformer đọc .class này, có thể đổi package/tên class
 * (qua ASM ClassRemapper) để đa dạng hoá giữa các lần build, rồi nhúng vào
 * jar output cùng với 3 file thư viện native (win/linux/mac) được đóng gói
 * sẵn trong thư mục resource tương ứng ("/novanative/<os>.bin").
 *
 * QUAN TRỌNG: nếu bạn đổi package/class name mặc định ("novanative.NativeBridge")
 * khi build file .class này, phải đổi tên hàm export trong stringdecrypt.c
 * theo đúng quy tắc JNI tương ứng.
 */
public final class NativeBridge {

    private NativeBridge() {
    }

    private static volatile boolean loaded = false;
    private static volatile Throwable loadError = null;

    static {
        try {
            loadNative();
            loaded = true;
        } catch (Throwable t) {
            loadError = t;
        }
    }

    private static void loadNative() throws Exception {
        String os = System.getProperty("os.name", "").toLowerCase();
        String arch = System.getProperty("os.arch", "").toLowerCase();
        String resourceName;
        String suffix;
        if (os.contains("win")) {
            resourceName = "/novanative/win-x64.bin";
            suffix = ".dll";
        } else if (os.contains("mac") || os.contains("darwin")) {
            boolean arm = arch.contains("aarch64") || arch.contains("arm");
            resourceName = arm ? "/novanative/mac-arm64.bin" : "/novanative/mac-x64.bin";
            suffix = ".dylib";
        } else {
            resourceName = "/novanative/linux-x64.bin";
            suffix = ".so";
        }

        InputStream in = NativeBridge.class.getResourceAsStream(resourceName);
        if (in == null) {
            throw new IllegalStateException("Native lib resource not found: " + resourceName);
        }

        byte[] data;
        try {
            java.io.ByteArrayOutputStream buf = new java.io.ByteArrayOutputStream();
            byte[] chunk = new byte[8192];
            int r;
            while ((r = in.read(chunk)) != -1) buf.write(chunk, 0, r);
            data = buf.toByteArray();
        } finally {
            in.close();
        }

        // XOR nhẹ chỉ để file .bin trong jar không khớp "magic bytes" ELF/PE/Mach-O
        // khi bị quét bằng `file`/AV signature đơn giản - KHÔNG phải mã hoá thật.
        for (int i = 0; i < data.length; i++) {
            data[i] = (byte) (data[i] ^ (0x5A + (i % 7)));
        }

        File tmp = File.createTempFile("novanative", suffix);
        tmp.deleteOnExit();
        FileOutputStream out = new FileOutputStream(tmp);
        try {
            out.write(data);
        } finally {
            out.close();
        }

        System.load(tmp.getAbsolutePath());
    }

    static native String decrypt0(char[] arr, long seed, int key, int classKey);

    /**
     * Entry point thực sự mà bytecode sinh ra ở các call-site gọi vào.
     * Nếu native lib load lỗi (thiếu file, sai OS/arch...), ném lỗi rõ ràng
     * thay vì để JVM crash mù mờ bằng UnsatisfiedLinkError khó hiểu.
     */
    public static String decrypt(char[] arr, long seed, int key, int classKey) {
        if (!loaded) {
            throw new IllegalStateException("Native string decryptor failed to load", loadError);
        }
        return decrypt0(arr, seed, key, classKey);
    }
}
