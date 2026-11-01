package net.spartanb312.grunt.process.transformers.misc

import net.spartanb312.genesis.kotlin.clazz
import net.spartanb312.genesis.kotlin.extensions.PUBLIC
import net.spartanb312.genesis.kotlin.extensions.STATIC
import net.spartanb312.genesis.kotlin.extensions.SUPER
import net.spartanb312.genesis.kotlin.extensions.insn.ACONST_NULL
import net.spartanb312.genesis.kotlin.extensions.insn.ALOAD
import net.spartanb312.genesis.kotlin.extensions.insn.ARETURN
import net.spartanb312.genesis.kotlin.extensions.insn.DRETURN
import net.spartanb312.genesis.kotlin.extensions.insn.DUP
import net.spartanb312.genesis.kotlin.extensions.insn.FRETURN
import net.spartanb312.genesis.kotlin.extensions.insn.INVOKESPECIAL
import net.spartanb312.genesis.kotlin.extensions.insn.INVOKESTATIC
import net.spartanb312.genesis.kotlin.extensions.insn.IRETURN
import net.spartanb312.genesis.kotlin.extensions.insn.LDC
import net.spartanb312.genesis.kotlin.extensions.insn.LRETURN
import net.spartanb312.genesis.kotlin.extensions.insn.RETURN
import net.spartanb312.genesis.kotlin.field
import net.spartanb312.genesis.kotlin.method
import net.spartanb312.genesis.kotlin.modify
import net.spartanb312.grunt.config.setting
import net.spartanb312.grunt.process.Transformer
import net.spartanb312.grunt.process.resource.NameGenerator
import net.spartanb312.grunt.process.resource.ResourceCache
import net.spartanb312.grunt.utils.extensions.isAbstract
import net.spartanb312.grunt.utils.extensions.isNative
import net.spartanb312.grunt.utils.logging.Logger
import org.objectweb.asm.Opcodes
import org.objectweb.asm.tree.AbstractInsnNode
import org.objectweb.asm.tree.ClassNode
import org.objectweb.asm.tree.InsnNode
import org.objectweb.asm.tree.MethodNode
import kotlin.random.Random

/**
 * Generates trash classes and trash methods (có gọi chéo lẫn nhau trong cùng class,
 * và tùy chọn được method thật gọi vào để trộn lẫn vào đồ thị gọi hàm thật).
 * Last update on 2024/10/12
 */
object TrashClassTransformer : Transformer("TrashClass", Category.Miscellaneous) {

    private val packages by setting("Package", "net/spartanb312/obf/")
    // Cùng cơ chế Dictionary với ClassRename/MethodRename -> tên class/method rác sinh ra
    // giống hệt format tên thật bị remap, không còn pattern "Trash"/"trash" để nhận dạng riêng.
    private val dictionary by setting("Dictionary", "Alphabet")
    private val prefix by setting("Prefix", "")
    private val count by setting("Count", 0)
    private val methodDictionary by setting("MethodDictionary", "Alphabet")
    private val methodPrefix by setting("MethodPrefix", "")
    private val methodCountMin by setting("MethodCountMin", 0)
    private val methodCountMax by setting("MethodCountMax", 0)
    private val crossCallChance by setting("CrossCallChance", 50) // % cơ hội 1 trash method gọi 1 trash method khác cùng class

    // Real -> Trash: method thật chèn lời gọi sang 1 trash method ngẫu nhiên (an toàn vì trash method không side-effect)
    // Lời gọi được bọc trong 1 nhánh chết (opaque predicate luôn false) thay vì gọi thẳng,
    // để buộc người phân tích phải chứng minh nhánh đó không bao giờ chạy mới loại được nó.
    private val realCallChance by setting("RealCallChance", 0) // % cơ hội 1 method thật được chèn lời gọi sang trash
    private val realCallExclusion by setting("RealCallExclusion", listOf())

    // % cơ hội trash method trả về giá trị đọc từ 1 field static thật (GETSTATIC) thay vì hằng số random,
    // để trash method trông như đang thao tác với state thật của chương trình. Chỉ ĐỌC field (không ghi),
    // nên vẫn an toàn tuyệt đối với hành vi gốc dù bị gọi ở đâu.
    private val realRefChance by setting("RealRefChance", 0)

    // sort code cho desc trả về, dùng để biết cách POP sau khi gọi chéo
    private enum class RetKind(val desc: String) {
        INT("()I"), BOOL("()Z"), FLOAT("()F"), LONG("()J"), DOUBLE("()D"), OBJ("()Ljava/lang/Object;")
    }

    private data class MethodSpec(val name: String, val kind: RetKind)

    // Tham chiếu tới 1 field static thật (public, không synthetic) dùng để "cắm" vào trash method
    private data class FieldRef(val owner: String, val name: String, val desc: String)

    // (ownerClassName, spec) của mọi trash method đã sinh ra trong lượt transform này,
    // dùng để cho method thật gọi chéo sang (RealCallChance).
    private val allTrashMethods = mutableListOf<Pair<String, MethodSpec>>()

    override fun ResourceCache.transform() {
        Logger.info(" - Generating trash classes...")
        allTrashMethods.clear()
        val fieldPool = collectRealFieldPool()
        val trashClasses = mutableListOf<ClassNode>()
        // 1 generator dùng xuyên suốt cho toàn bộ class rác của lượt này (giống ClassRename:
        // 1 NameGenerator cho cả run -> tên tuần tự theo index, không còn "random5" lộ dấu hiệu).
        val classNameGenerator = NameGenerator.getByName(dictionary)
        val methodNameGenerator = NameGenerator.getByName(methodDictionary)
        var totalMethods = 0
        repeat(count) {
            val name = packages + prefix + classNameGenerator.nextName()
            val methodCount =
                if (methodCountMax > methodCountMin) Random.nextInt(methodCountMin, methodCountMax + 1)
                else methodCountMin
            val generated = generateClass(name, (0..2).random(), methodCount, fieldPool, methodNameGenerator)
            totalMethods += methodCount
            trashClasses.add(generated)
        }
        trashClasses.forEach { addClass(it) }
        Logger.info("    Generated ${trashClasses.size} trash classes with $totalMethods trash methods")

        if (realCallChance > 0 && allTrashMethods.isNotEmpty()) {
            Logger.info(" - Injecting calls from real methods into trash methods...")
            var injected = 0
            nonExcluded.asSequence()
                .filter { c -> realCallExclusion.none { c.name.startsWith(it) } }
                .forEach { classNode ->
                    classNode.methods
                        .filter { !it.isAbstract && !it.isNative && it.instructions != null && it.instructions.size() > 0 }
                        .forEach { methodNode ->
                            if (Random.nextInt(100) < realCallChance) {
                                injectTrashCall(methodNode)
                                injected++
                            }
                        }
                }
            Logger.info("    Injected $injected calls to trash methods")
        }
    }

    /**
     * Chèn 1 lời gọi tới trash method ngẫu nhiên vào đầu method thật - nhưng KHÔNG gọi thẳng,
     * mà bọc trong 1 nhánh chết (dead branch) được canh giữ bởi opaque predicate:
     *
     *   x * (x + 1) % 2   luôn luôn == 0 (tích 2 số nguyên liên tiếp luôn chẵn)
     *
     * nên `IFEQ skip` LUÔN nhảy qua, lời gọi trash bên dưới KHÔNG BAO GIỜ thực thi ở runtime.
     * Về mặt tĩnh, 1 decompiler/deobfuscator thông thường chỉ thấy 1 nhánh if bình thường dẫn tới
     * lời gọi method - muốn loại bỏ an toàn, nó phải tự chứng minh được predicate luôn false
     * (constant-fold phép nhân + mod) thay vì chỉ nhìn pattern "return constant" là biết ngay là rác
     * như trước đây. Vẫn an toàn 100% với hành vi gốc vì nhánh gọi trash không bao giờ chạy.
     */
    private fun injectTrashCall(methodNode: MethodNode) {
        val (owner, spec) = allTrashMethods.random()
        val skip = org.objectweb.asm.tree.LabelNode()
        val x = Random.nextInt(2, 1_000_000)

        val call = org.objectweb.asm.tree.InsnList()
        call.add(org.objectweb.asm.tree.LdcInsnNode(x))
        call.add(org.objectweb.asm.tree.LdcInsnNode(x + 1))
        call.add(InsnNode(Opcodes.IMUL))
        call.add(org.objectweb.asm.tree.LdcInsnNode(2))
        call.add(InsnNode(Opcodes.IREM))
        call.add(org.objectweb.asm.tree.JumpInsnNode(Opcodes.IFEQ, skip)) // luôn nhảy -> nhánh dưới luôn chết
        call.add(org.objectweb.asm.tree.MethodInsnNode(Opcodes.INVOKESTATIC, owner, spec.name, spec.kind.desc, false))
        call.add(popFor(spec.kind))
        call.add(skip)

        val first: AbstractInsnNode? = methodNode.instructions.first
        if (first != null) methodNode.instructions.insertBefore(first, call)
        else methodNode.instructions.insert(call)
    }

    /**
     * Quét toàn bộ class không bị loại trừ, gom các field static public (không synthetic)
     * theo descriptor, để trash method có thể GETSTATIC chúng thay vì trả hằng số vô nghĩa.
     * Chỉ dùng để ĐỌC (GETSTATIC) -> an toàn tuyệt đối, không có side-effect.
     */
    private fun ResourceCache.collectRealFieldPool(): Map<RetKind, List<FieldRef>> {
        val map = RetKind.entries.associateWith { mutableListOf<FieldRef>() }
        nonExcluded.forEach { c ->
            c.fields?.forEach { f ->
                val acc = f.access
                if (acc and Opcodes.ACC_STATIC != 0 &&
                    acc and Opcodes.ACC_PUBLIC != 0 &&
                    acc and Opcodes.ACC_SYNTHETIC == 0
                ) {
                    val ref = FieldRef(c.name, f.name, f.desc)
                    when (f.desc) {
                        "I" -> map.getValue(RetKind.INT).add(ref)
                        "Z" -> map.getValue(RetKind.BOOL).add(ref)
                        "F" -> map.getValue(RetKind.FLOAT).add(ref)
                        "J" -> map.getValue(RetKind.LONG).add(ref)
                        "D" -> map.getValue(RetKind.DOUBLE).add(ref)
                        else -> if (f.desc.startsWith("L") || f.desc.startsWith("["))
                            map.getValue(RetKind.OBJ).add(ref)
                    }
                }
            }
        }
        return map
    }

    private fun generateClass(
        owner: String,
        type: Int,
        methodCount: Int,
        fieldPool: Map<RetKind, List<FieldRef>>,
        methodNameGenerator: NameGenerator
    ): ClassNode {
        val superName = when (type) {
            0 -> "java/util/concurrent/ConcurrentHashMap"
            1 -> "java/util/concurrent/ConcurrentLinkedDeque"
            else -> "java/util/concurrent/ConcurrentSkipListMap"
        }
        return clazz(
            PUBLIC + SUPER,
            owner,
            superName
        ).modify {
            +field(
                PUBLIC + STATIC,
                "c",
                "I",
                null,
                8964
            )
            +method(
                PUBLIC,
                "<init>",
                "()V"
            ) {
                INSTRUCTIONS {
                    ALOAD(0)
                    DUP
                    INVOKESPECIAL(superName, "<init>", "()V")
                    RETURN
                }
                MAXS(1, 1)
            }

            // Tạo trước danh sách tên + kiểu trả về cho tất cả trash method trong class này,
            // để mỗi method chỉ gọi chéo sang method đứng SAU nó trong danh sách (DAG, không vòng).
            val specs = (0 until methodCount).map {
                MethodSpec(methodPrefix + methodNameGenerator.nextName(), RetKind.entries.toTypedArray().random())
            }
            specs.forEach { allTrashMethods.add(owner to it) }

            specs.forEachIndexed { index, spec ->
                +generateTrashMethod(owner, spec, specs, index, fieldPool)
            }
        }
    }

    private fun generateTrashMethod(
        owner: String,
        self: MethodSpec,
        allSpecs: List<MethodSpec>,
        selfIndex: Int,
        fieldPool: Map<RetKind, List<FieldRef>>
    ) = method(PUBLIC + STATIC, self.name, self.kind.desc) {
        INSTRUCTIONS {
            // Random gọi chéo sang 1 trash method khác cùng class (nếu có) trước khi return.
            // Chỉ gọi method có index LỚN HƠN selfIndex -> đồ thị gọi luôn là DAG,
            // không thể tạo vòng kiểu a gọi b, b gọi c, c gọi lại a (tránh StackOverflowError).
            val others = allSpecs.filterIndexed { i, _ -> i > selfIndex }
            if (others.isNotEmpty() && Random.nextInt(100) < crossCallChance) {
                val target = others.random()
                INVOKESTATIC(owner, target.name, target.kind.desc)
                +popFor(target.kind)
            }

            // Nếu trúng RealRefChance và có field thật cùng kiểu -> GETSTATIC field đó rồi return thẳng,
            // thay vì trả hằng số vô nghĩa. Chỉ ĐỌC field nên tuyệt đối an toàn, nhưng khiến trash method
            // trông như đang thao tác state thật, không còn là "return constant" dễ nhận diện.
            val candidates = fieldPool[self.kind].orEmpty()
            val realRef = if (candidates.isNotEmpty() && Random.nextInt(100) < realRefChance)
                candidates.random() else null

            if (realRef != null) {
                +org.objectweb.asm.tree.FieldInsnNode(Opcodes.GETSTATIC, realRef.owner, realRef.name, realRef.desc)
                when (self.kind) {
                    RetKind.INT, RetKind.BOOL -> IRETURN
                    RetKind.FLOAT -> FRETURN
                    RetKind.LONG -> LRETURN
                    RetKind.DOUBLE -> DRETURN
                    RetKind.OBJ -> ARETURN
                }
            } else when (self.kind) {
                RetKind.INT -> {
                    LDC(Random.nextInt())
                    IRETURN
                }

                RetKind.BOOL -> {
                    LDC(if (Random.nextBoolean()) 1 else 0)
                    IRETURN
                }

                RetKind.FLOAT -> {
                    LDC(Random.nextFloat())
                    FRETURN
                }

                RetKind.LONG -> {
                    LDC(Random.nextLong())
                    LRETURN
                }

                RetKind.DOUBLE -> {
                    LDC(Random.nextDouble())
                    DRETURN
                }

                RetKind.OBJ -> {
                    ACONST_NULL
                    ARETURN
                }
            }
        }
        MAXS(2, 0)
    }

    private fun popFor(kind: RetKind): InsnNode = when (kind) {
        RetKind.LONG, RetKind.DOUBLE -> InsnNode(Opcodes.POP2)
        else -> InsnNode(Opcodes.POP)
    }

}