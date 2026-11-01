package net.spartanb312.grunt.process.transformers.encrypt

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import net.spartanb312.genesis.kotlin.clazz
import net.spartanb312.genesis.kotlin.extensions.*
import net.spartanb312.genesis.kotlin.extensions.insn.*
import net.spartanb312.genesis.kotlin.field
import net.spartanb312.genesis.kotlin.instructions
import net.spartanb312.genesis.kotlin.method
import net.spartanb312.genesis.kotlin.modify
import net.spartanb312.grunt.config.Configs
import net.spartanb312.grunt.config.setting
import net.spartanb312.grunt.process.Transformer
import net.spartanb312.grunt.process.resource.NameGenerator
import net.spartanb312.grunt.process.resource.ResourceCache
import net.spartanb312.grunt.process.transformers.rename.ReflectionSupportTransformer
import net.spartanb312.grunt.utils.count
import net.spartanb312.grunt.utils.logging.Logger
import org.objectweb.asm.Opcodes
import org.objectweb.asm.tree.ClassNode
import org.objectweb.asm.tree.LdcInsnNode
import kotlin.random.Random

/**
 * Mỗi string literal được tách ra thành 1 class RIÊNG:
 * class đó tự chứa data mã hoá (char[], build bằng CASTORE - an toàn tuyệt đối với mọi
 * ký tự Unicode vì không đụng tới CONSTANT_Utf8/giới hạn 64KB của constant pool),
 * tự giải mã trong <clinit> và lưu kết quả vào 1 field "public static final String".
 * Nơi dùng string gốc chỉ còn lại GETSTATIC sang field đó.
 *
 * Vì mỗi class chỉ xử lý đúng 1 string nên không method nào trong class gốc hay class
 * mới có thể phình to (large method) dù class gốc có bao nhiêu string, hay string dài/unicode
 * cỡ nào - mỗi class mới chỉ to tuyến tính theo độ dài CHÍNH string đó, hoàn toàn tách biệt.
 *
 * Dùng chung logic mã hoá/giải mã (encrypt + createDecryptMethod) với StringEncryptTransformer
 * để không trùng lặp code và đảm bảo cùng 1 chuẩn mã hoá.
 */
object StringClassEncryptTransformer : Transformer("StringClassEncrypt", Category.Encryption) {

    private val packages by setting("Package", "net/spartanb312/obf/str/")
    // Cùng cơ chế Dictionary với ClassRename/FieldRename/MethodRename -> tên class/field/method
    // sinh ra giống hệt format tên thật bị remap, không còn pattern "S" + random để nhận dạng riêng.
    private val dictionary by setting("Dictionary", "Alphabet")
    private val prefix by setting("Prefix", "")
    private val minStringLength by setting("MinStringLength", 0) // string ngắn hơn thì giữ nguyên, không tách class
    private val replaceInvokeDynamics by setting("ReplaceInvokeDynamics", true)
    private val exclusion by setting("Exclusion", listOf())

    // 3 generator riêng (cùng dictionary) dùng xuyên suốt cả lượt transform này, an toàn khi chạy
    // song song vì NameGenerator đếm bằng AtomicInteger.
    private lateinit var classNameGenerator: NameGenerator
    private lateinit var fieldNameGenerator: NameGenerator
    private lateinit var decryptNameGenerator: NameGenerator

    private val String.reflectionExcluded
        get() = ReflectionSupportTransformer.enabled && ReflectionSupportTransformer.strBlacklist.contains(this)

    private data class FieldRef(val owner: String, val name: String)

    override fun ResourceCache.transform() {
        Logger.info(" - Encrypting strings into dedicated classes...")
        classNameGenerator = NameGenerator.getByName(dictionary)
        fieldNameGenerator = NameGenerator.getByName(dictionary)
        decryptNameGenerator = NameGenerator.getByName(dictionary)
        val generatedClasses = mutableListOf<ClassNode>()

        val count = count {
            runBlocking {
                nonExcluded.asSequence()
                    .filter { c -> c.version > Opcodes.V1_5 && exclusion.none { c.name.startsWith(it) } }
                    .forEach { classNode ->
                        fun job() {
                            val created = transformClass(classNode)
                            if (created.isNotEmpty()) synchronized(generatedClasses) { generatedClasses.addAll(created) }
                        }
                        if (Configs.Settings.parallel) launch(Dispatchers.Default) { job() } else job()
                    }
            }
        }.get()

        generatedClasses.forEach { addClass(it) }
        Logger.info("    Generated ${generatedClasses.size} string classes, encrypted $count strings")
    }

    /**
     * Xử lý 1 class: tìm mọi LDC string hợp lệ, với mỗi string (duy nhất trong phạm vi class này)
     * sinh 1 class giải mã riêng, rồi thay LDC bằng GETSTATIC trỏ sang field của class đó.
     * Trả về danh sách class mới sinh ra để caller add vào ResourceCache.
     */
    private fun transformClass(classNode: ClassNode): List<ClassNode> {
        if (replaceInvokeDynamics) StringEncryptTransformer.replaceInvokeDynamics(classNode, null)

        val newClasses = mutableListOf<ClassNode>()
        val stringToField = mutableMapOf<String, FieldRef>()

        classNode.methods.forEach { methodNode ->
            methodNode.instructions.forEach { insn ->
                if (insn is LdcInsnNode && insn.cst is String) {
                    val original = insn.cst as String
                    if (original.length < minStringLength) return@forEach
                    if (original.reflectionExcluded) return@forEach
                    if (!stringToField.containsKey(original)) {
                        val (genClass, fieldName) = generateStringClass(original)
                        newClasses.add(genClass)
                        stringToField[original] = FieldRef(genClass.name, fieldName)
                    }
                }
            }
        }

        if (stringToField.isNotEmpty()) {
            classNode.methods.forEach { methodNode ->
                methodNode.instructions.asSequence()
                    .filter { it is LdcInsnNode && it.cst is String && stringToField.containsKey(it.cst) }
                    .toList()
                    .forEach { insn ->
                        insn as LdcInsnNode
                        val ref = stringToField.getValue(insn.cst as String)
                        methodNode.instructions.insert(insn, instructions {
                            GETSTATIC(ref.owner, ref.name, "Ljava/lang/String;")
                        })
                        methodNode.instructions.remove(insn)
                    }
            }
        }

        return newClasses
    }

    /**
     * Sinh 1 class mới chứa đúng 1 string đã mã hoá + method giải mã + <clinit> tự giải mã
     * vào field "public static final String" duy nhất của class.
     */
    private fun generateStringClass(original: String): Pair<ClassNode, String> {
        val className = packages + prefix + classNameGenerator.nextName()
        val fieldName = fieldNameGenerator.nextName()
        val decryptName = decryptNameGenerator.nextName()
        val classKey = Random.nextInt()
        val key = Random.nextInt()
        val seed = Random.nextLong(100000L)
        val encrypted = StringEncryptTransformer.encrypt(original.toCharArray(), seed, key, classKey)

        val classNode = clazz(PUBLIC + SUPER, className, "java/lang/Object")
        val decryptMethod = StringEncryptTransformer.createDecryptMethod(classNode, decryptName, classKey)

        classNode.modify {
            +field(PUBLIC + STATIC + FINAL, fieldName, "Ljava/lang/String;", null, null)
            +decryptMethod
            +method(STATIC, "<clinit>", "()V") {
                INSTRUCTIONS {
                    // Build char[] bằng CASTORE theo từng code unit UTF-16 - an toàn với mọi
                    // ký tự Unicode (kể cả surrogate pair/emoji), không đụng CONSTANT_Utf8.
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
                    INVOKESTATIC(className, decryptMethod.name, decryptMethod.desc, false)
                    PUTSTATIC(className, fieldName, "Ljava/lang/String;")
                    RETURN
                }
                MAXS(4, 0)
            }
        }

        return classNode to fieldName
    }

}