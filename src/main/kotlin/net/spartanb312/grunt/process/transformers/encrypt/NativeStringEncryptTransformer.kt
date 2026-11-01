package net.spartanb312.grunt.process.transformers.encrypt

import net.spartanb312.genesis.kotlin.extensions.insn.*
import net.spartanb312.genesis.kotlin.instructions
import net.spartanb312.grunt.config.Configs
import net.spartanb312.grunt.config.setting
import net.spartanb312.grunt.process.MethodProcessor
import net.spartanb312.grunt.process.Transformer
import net.spartanb312.grunt.process.resource.ResourceCache
import net.spartanb312.grunt.utils.logging.Logger
import org.objectweb.asm.ClassReader
import org.objectweb.asm.Opcodes
import org.objectweb.asm.commons.ClassRemapper
import org.objectweb.asm.commons.SimpleRemapper
import org.objectweb.asm.tree.ClassNode
import org.objectweb.asm.tree.LdcInsnNode
import org.objectweb.asm.tree.MethodNode
import java.io.File
import kotlin.random.Random

/**
 * Mã hóa chuỗi bằng thuật toán giải mã chạy NGOÀI JVM, trong 1 thư viện
 * native (JNI) thay vì bằng 1 method Java nằm sẵn trong class file.
 *
 * Khác biệt so với [StringEncryptTransformer]: StringEncryptTransformer sinh
 * ra 1 method Java chứa toàn bộ logic giải mã - ai hook/log method đó
 * (reflection, javaagent, debugger) là lấy được chuỗi gốc ngay lập tức.
 * Transformer này thay bằng 1 lời gọi `native` sang file .dll/.so/.dylib
 * đi kèm - logic giải mã nằm trong code máy, không còn trong bytecode Java
 * để hook theo cách thông thường nữa.
 *
 * Yêu cầu trước khi bật transformer này:
 *   1. Build thư viện native từ `native/stringdecrypt/` (xem README ở đó),
 *      ra 3 file: win-x64, linux-x64, mac-x64(+mac-arm64) - có thể build thủ
 *      công hoặc để GitHub Actions build hộ (native/stringdecrypt có sẵn
 *      workflow).
 *   2. Đặt 3 file đó (tên gốc: novanative.dll / libnovanative.so /
 *      libnovanative.dylib) vào thư mục [nativeLibsDir], đổi tên theo đúng
 *      [winLibName]/[linuxLibName]/[macLibName]/[macArmLibName].
 *   3. [buildSecret] trong config PHẢI khớp đúng giá trị `-DBUILD_SECRET=...`
 *      lúc build thư viện native đó - sai 1 bit là giải mã ra rác.
 *
 * LƯU Ý QUAN TRỌNG (giới hạn thực tế, không nên quảng cáo quá mức):
 *   - Thư viện native vẫn CÓ TRONG jar output (chỉ bị XOR nhẹ để né quét
 *     "magic bytes" đơn giản) - 1 người kiên trì vẫn trích xuất + disassemble
 *     file .so/.dll đó được (bằng IDA/Ghidra...). Cái transformer này chặn là
 *     các công cụ hook Ở TẦNG JVM (reflection, java agent bật log mọi lời
 *     gọi method) - không phải "không thể bẻ được".
 *   - [buildSecret] mặc định double-checked qua XOR với classKey - vẫn là 1
 *     hằng số cố định trong file .so nếu bạn không đổi nó, KHÔNG phải key
 *     theo từng máy người chơi. Muốn mạnh hơn (key đổi theo máy chạy), phải
 *     tự mở rộng phần C để lấy thêm entropy từ máy (xem comment cuối file).
 */
object NativeStringEncryptTransformer : Transformer("NativeStringEncrypt", Category.Encryption), MethodProcessor {

    private val exclusion by setting("Exclusion", listOf())
    private val buildSecret by setting("BuildSecret", 0)

    private val nativeLibsDir by setting("NativeLibsDir", "native-libs/")
    private val winLibName by setting("WinLibName", "win-x64.bin")
    private val linuxLibName by setting("LinuxLibName", "linux-x64.bin")
    private val macLibName by setting("MacLibName", "mac-x64.bin")
    private val macArmLibName by setting("MacArmLibName", "mac-arm64.bin")

    // Phải khớp đúng package/class mà stringdecrypt.c export (Java_<pkg>_<Class>_decrypt0).
    // Đổi giá trị này -> phải build lại .so/.dll/.dylib với tên export tương ứng (xem log cảnh báo).
    private val bridgePackage by setting("BridgePackage", "novanative")
    private val bridgeClassName by setting("BridgeClassName", "NativeBridge")

    private const val TEMPLATE_RESOURCE = "/native/NativeBridge.class"
    private const val GOLDEN = -1640531527 // 0x9E3779B9, giống hệt StringEncryptTransformer, không phải bí mật
    private const val LCG_MUL = 1103515245
    private const val LCG_ADD = 12345

    private var bridgeInternalName = "novanative/NativeBridge"

    /** Mangling tên theo quy tắc JNI: '/' -> '_', '_' -> '_1' (đơn giản hóa, đủ dùng cho package/class ascii thường). */
    private fun jniMangle(internalName: String): String =
        internalName.replace("_", "_1").replace("/", "_")

    override fun ResourceCache.transform() {
        val defaultBridgeName = "$bridgePackage/$bridgeClassName"
        if (defaultBridgeName != "novanative/NativeBridge") {
            val requiredSymbol = "Java_${jniMangle(defaultBridgeName)}_decrypt0"
            Logger.warn(
                "    [NativeStringEncrypt] BridgePackage/BridgeClassName đã bị đổi khỏi mặc định " +
                        "(novanative/NativeBridge) -> phải build lại stringdecrypt.c, đổi tên hàm export " +
                        "thành '$requiredSymbol', nếu không JVM sẽ ném UnsatisfiedLinkError lúc chạy."
            )
        }

        if (!loadBridgeTemplate(this)) return
        if (!loadNativeLibResources(this)) {
            Logger.error("    [NativeStringEncrypt] Thiếu thư viện native trong '$nativeLibsDir', bỏ qua transformer này.")
            Logger.error("    Xem native/stringdecrypt/README.md để build, hoặc tắt NativeStringEncrypt trong config.")
            return
        }

        Logger.info(" - Encrypting strings (native/JNI)...")
        var total = 0
        nonExcluded.asSequence()
            .filter { c -> c.version > Opcodes.V1_5 && c.name != bridgeInternalName && exclusion.none { c.name.startsWith(it) } }
            .forEach { classNode -> total += transformClass(classNode, null) }
        Logger.info("    Encrypted $total strings via native decryptor")
    }

    override fun transformMethod(owner: ClassNode, method: MethodNode) {
        if (owner.name == bridgeInternalName) return
        transformClass(owner, method)
    }

    /**
     * Đọc .class loader/bridge đã compile sẵn (bundled resource trong chính
     * Grunt, KHÔNG sinh bằng ASM tay) và thêm vào project đang được obfuscate.
     * Class này được loại khỏi mọi transformer khác (rename, shrink, control
     * flow...) qua `Configs.Settings.exclusions` để không bị phá cấu trúc
     * loader (static init, try/catch, System.load...).
     */
    private fun loadBridgeTemplate(cache: ResourceCache): Boolean {
        val bytes = javaClass.getResourceAsStream(TEMPLATE_RESOURCE)?.readBytes()
        if (bytes == null) {
            Logger.error("    [NativeStringEncrypt] Không tìm thấy resource $TEMPLATE_RESOURCE trong Grunt - thiếu bridge template.")
            return false
        }

        val reader = ClassReader(bytes)
        val targetName = "$bridgePackage/$bridgeClassName"
        val classNode = ClassNode()
        if (targetName == "novanative/NativeBridge") {
            reader.accept(classNode, ClassReader.EXPAND_FRAMES)
        } else {
            val remapper = SimpleRemapper(mapOf("novanative/NativeBridge" to targetName))
            reader.accept(ClassRemapper(classNode, remapper), ClassReader.EXPAND_FRAMES)
        }

        bridgeInternalName = classNode.name
        cache.addClass(classNode)
        // Bảo vệ bridge khỏi mọi transformer khác chạy sau nó (rename/controlflow/shrink/...)
        Configs.Settings.exclusions = Configs.Settings.exclusions + bridgeInternalName
        return true
    }

    /**
     * Đọc 4 file thư viện native đã build (RAW .dll/.so/.dylib, XOR ở bước
     * này - không phải XOR trước trong file trên đĩa) từ [nativeLibsDir] và
     * nhúng vào jar output dưới dạng resource, đúng đường dẫn mà NativeBridge
     * (phía Java) tìm bằng `getResourceAsStream`.
     */
    private fun loadNativeLibResources(cache: ResourceCache): Boolean {
        val dir = File(nativeLibsDir)
        val files = mapOf(
            winLibName to "win-x64.bin",
            linuxLibName to "linux-x64.bin",
            macLibName to "mac-x64.bin",
            macArmLibName to "mac-arm64.bin",
        )
        var foundAny = false
        files.forEach { (srcName, resName) ->
            val f = File(dir, srcName)
            if (f.exists()) {
                val raw = f.readBytes()
                val xored = ByteArray(raw.size) { i -> (raw[i].toInt() xor (0x5A + (i % 7))).toByte() }
                cache.resources["$bridgePackage/$resName"] = xored
                foundAny = true
            } else {
                Logger.warn("    [NativeStringEncrypt] Thiếu ${f.path}, platform tương ứng sẽ không chạy được (UnsatisfiedLinkError).")
            }
        }
        return foundAny
    }

    /** Port Kotlin 1:1 của thuật toán trong stringdecrypt.c (Java_..._decrypt0). */
    private fun encrypt(cArray: CharArray, seed: Long, key: Int, rawClassKey: Int): String {
        val effClassKey = rawClassKey xor buildSecret
        var n = effClassKey xor key
        var l = seed
        val out = CharArray(cArray.size)
        for (i in cArray.indices) {
            val mask = (n xor l.toInt()) + i * GOLDEN
            out[i] = (cArray[i].code xor mask).toChar()
            n = n * LCG_MUL + LCG_ADD
            l = l xor i.toLong()
        }
        return String(out)
    }

    private fun transformClass(classNode: ClassNode, onlyObfuscate: MethodNode?): Int {
        var encryptedCount = 0
        val rawClassKey = Random.nextInt()
        classNode.methods.forEach { methodNode ->
            if (onlyObfuscate != null && onlyObfuscate != methodNode) return@forEach
            methodNode.instructions.asSequence()
                .filter { it is LdcInsnNode && it.cst is String }
                .shuffled()
                .forEach { instruction ->
                    val originalString = (instruction as LdcInsnNode).cst as String
                    val key = Random.nextInt()
                    val seed = Random.nextLong(100000L)
                    val encrypted = encrypt(originalString.toCharArray(), seed, key, rawClassKey)
                    methodNode.instructions.insert(instruction, instructions {
                        INT(encrypted.length)
                        NEWARRAY(Opcodes.T_CHAR)
                        for (i in encrypted.indices) {
                            DUP
                            INT(i)
                            INT(encrypted[i].code)
                            CASTORE
                        }
                        LONG(seed)
                        INT(key)
                        INT(rawClassKey)
                        INVOKESTATIC(bridgeInternalName, "decrypt", "([CJII)Ljava/lang/String;", false)
                    })
                    methodNode.instructions.remove(instruction)
                    encryptedCount++
                }
        }
        return encryptedCount
    }
}

/*
 * Muốn key còn phụ thuộc cả vào runtime state (ví dụ identity hash của
 * classloader, hoặc thời điểm JVM khởi động) thay vì chỉ 1 buildSecret cố
 * định: thêm tham số đó vào chữ ký `decrypt0` (ví dụ 1 jlong lấy từ
 * System.nanoTime() tại thời điểm load native lib, lưu vào 1 field static
 * trong NativeBridge, truyền kèm mỗi lần gọi) và XOR nó vào effClassKey ở cả
 * 2 phía (C và Kotlin encrypt() ở trên) theo đúng công thức giống nhau.
 * Lưu ý: cách này KHÔNG chống được hook ở tầng JVM tốt hơn buildSecret tĩnh -
 * nó chỉ chống phân tích tĩnh offline (dump string ra đọc mà không chạy JVM).
 */
