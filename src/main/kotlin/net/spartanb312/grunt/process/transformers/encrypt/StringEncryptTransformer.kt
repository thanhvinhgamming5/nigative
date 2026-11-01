package net.spartanb312.grunt.process.transformers.encrypt

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import net.spartanb312.genesis.kotlin.clinit
import net.spartanb312.genesis.kotlin.extensions.*
import net.spartanb312.genesis.kotlin.extensions.insn.*
import net.spartanb312.genesis.kotlin.field
import net.spartanb312.genesis.kotlin.instructions
import net.spartanb312.genesis.kotlin.method
import net.spartanb312.grunt.config.Configs
import net.spartanb312.grunt.config.setting
import net.spartanb312.grunt.process.MethodProcessor
import net.spartanb312.grunt.process.Transformer
import net.spartanb312.grunt.process.resource.ResourceCache
import net.spartanb312.grunt.process.transformers.rename.ReflectionSupportTransformer
import net.spartanb312.grunt.utils.count
import net.spartanb312.grunt.utils.extensions.isInterface
import net.spartanb312.grunt.utils.getRandomString
import net.spartanb312.grunt.utils.logging.Logger
import org.objectweb.asm.Handle
import org.objectweb.asm.Opcodes
import org.objectweb.asm.tree.*
import kotlin.random.Random

/**
 * Encrypt strings
 * Last update on 2024/12/28
 */
object StringEncryptTransformer : Transformer("StringEncrypt", Category.Encryption), MethodProcessor {

    private val arrayed by setting("Arrayed", false)
    private val replaceInvokeDynamics by setting("ReplaceInvokeDynamics", true)
    private val exclusion by setting("Exclusion", listOf())

    // Per-class chance to skip the shared pool field/array-init-method layout
    // entirely and decrypt each string inline at its own call-site instead.
    // Diversifies the static shape between classes (no field+clinit+init-method
    // to fingerprint in some classes at all), at the cost of a slightly bigger
    // method body per call-site.
    private val inlineChance by setting("InlineNoPoolChance", 30) // Range 0..100
    private val inlineMaxStrings by setting("InlineMaxStrings", 40) // Skip inline technique above this many strings

    // Build-time constants shared by the keystream/multiplicative variants below.
    // Not secrets - just arbitrary odd/large constants to spread bits around.
    private const val GOLDEN = -1640531527 // 0x9E3779B9
    private const val LCG_MUL = 1103515245
    private const val LCG_ADD = 12345

    /**
     * One "shape" of string encryption. Each variant pairs a build-time [encrypt]
     * (verified against its decrypt bytecode in Python before being hand-written
     * here) with the [createDecryptMethod] that reproduces it in ASM. A class
     * picks exactly one variant (see [pickVariant]) so every string in that class
     * decrypts the same way - this keeps the existing one-field/one-method-per-class
     * layout, it just randomizes *which* algorithm that method implements, so
     * different classes decompile to visibly different decrypt routines.
     *
     * [encrypt] returns the scrambled char data plus whatever int should actually
     * be passed as the method's 3rd (int) argument at the call site - for most
     * variants that's just [key], but Variant D passes a precomputed modular
     * inverse instead of the multiplier itself.
     */
    private sealed class Variant {
        abstract fun encrypt(cArray: CharArray, seed: Long, key: Int, classKey: Int): Pair<String, Int>
        abstract fun createDecryptMethod(classNode: ClassNode, methodName: String, classKey: Int): MethodNode
    }

    /**
     * Variant A (baseline): XOR chain + ISUB + IMUL + IOR, state evolves by
     * rotating the key by `i & 0xFF` each round. See [encrypt]/[createDecryptMethod]
     * at the bottom of the file - kept as free functions (not wrapped here) since
     * [net.spartanb312.grunt.process.transformers.encrypt.StringClassEncryptTransformer]
     * calls them directly by name.
     */
    private object VariantA : Variant() {
        override fun encrypt(cArray: CharArray, seed: Long, key: Int, classKey: Int): Pair<String, Int> =
            StringEncryptTransformer.encrypt(cArray, seed, key, classKey) to key

        override fun createDecryptMethod(classNode: ClassNode, methodName: String, classKey: Int): MethodNode =
            StringEncryptTransformer.createDecryptMethod(classNode, methodName, classKey)
    }

    /**
     * Variant B: LCG keystream (same recurrence shape as java.util.Random:
     * n = n*MUL + ADD). Unlike A, each character's mask only depends on the
     * running state, not on the character itself - a pure keystream, so
     * encrypt and decrypt are the literal same loop (XOR is self-inverse).
     */
    private object VariantB : Variant() {
        override fun encrypt(cArray: CharArray, seed: Long, key: Int, classKey: Int): Pair<String, Int> {
            var n = classKey xor key
            var l = seed
            val out = CharArray(cArray.size)
            for (i in cArray.indices) {
                val mask = (n xor l.toInt()) + i * GOLDEN
                out[i] = (cArray[i].code xor mask).toChar()
                n = n * LCG_MUL + LCG_ADD
                l = l xor i.toLong()
            }
            return String(out) to key
        }

        override fun createDecryptMethod(classNode: ClassNode, methodName: String, classKey: Int): MethodNode = method(
            (if (classNode.isInterface) PUBLIC else PRIVATE) + STATIC,
            methodName,
            "([CJI)Ljava/lang/String;"
        ) {
            INSTRUCTIONS {
                // n(4) = classKey xor key(3)
                LABEL(L["L0"])
                INT(classKey)
                ILOAD(3)
                IXOR
                ISTORE(4)
                // i(5) = 0
                LABEL(L["L1"])
                ICONST_0
                ISTORE(5)
                LABEL(L["L2"])
                FRAME(Opcodes.F_APPEND, 2, arrayOf(Opcodes.INTEGER, Opcodes.INTEGER), 0, null)
                ILOAD(5)
                ALOAD(0)
                ARRAYLENGTH
                IF_ICMPGE(L["L3"])
                // mask(6) = (n xor (int)l) + i*GOLDEN
                LABEL(L["L4"])
                ILOAD(4)
                LLOAD(1)
                L2I
                IXOR
                ILOAD(5)
                INT(GOLDEN)
                IMUL
                IADD
                ISTORE(6)
                // arr[i] = (char)(arr[i] xor mask)
                LABEL(L["L5"])
                ALOAD(0)
                ILOAD(5)
                ALOAD(0)
                ILOAD(5)
                CALOAD
                ILOAD(6)
                IXOR
                I2C
                CASTORE
                // n = n*MUL + ADD
                LABEL(L["L6"])
                ILOAD(4)
                INT(LCG_MUL)
                IMUL
                INT(LCG_ADD)
                IADD
                ISTORE(4)
                // l = l xor i
                LABEL(L["L7"])
                LLOAD(1)
                ILOAD(5)
                I2L
                LXOR
                LSTORE(1)
                LABEL(L["L8"])
                IINC(5, 1)
                GOTO(L["L2"])
                LABEL(L["L3"])
                FRAME(Opcodes.F_CHOP, 1, null, 0, null)
                NEW("java/lang/String")
                DUP
                ALOAD(0)
                INVOKESPECIAL("java/lang/String", "<init>", "([C)V")
                ARETURN
                LABEL(L["L9"])
            }
            MAXS(5, 7)
        }
    }

    /**
     * Variant C: keystream + feedback (CFB-style chaining). The mask for
     * character i mixes a rotate-left of the state by i with the *previous*
     * ciphertext character, so characters are no longer independent of each
     * other - unlike A/B, where the state only depends on the index.
     */
    private object VariantC : Variant() {
        override fun encrypt(cArray: CharArray, seed: Long, key: Int, classKey: Int): Pair<String, Int> {
            var n = classKey xor key
            val l = seed
            var fb = l.toInt() xor key
            val out = CharArray(cArray.size)
            for (i in cArray.indices) {
                val rot = Integer.rotateLeft(n, i)
                val mask = rot xor l.toInt() xor fb
                val cc = (cArray[i].code xor mask).toChar()
                out[i] = cc
                fb = cc.code
                n += i + 1
            }
            return String(out) to key
        }

        override fun createDecryptMethod(classNode: ClassNode, methodName: String, classKey: Int): MethodNode = method(
            (if (classNode.isInterface) PUBLIC else PRIVATE) + STATIC,
            methodName,
            "([CJI)Ljava/lang/String;"
        ) {
            INSTRUCTIONS {
                // n(4) = classKey xor key(3)
                LABEL(L["L0"])
                INT(classKey)
                ILOAD(3)
                IXOR
                ISTORE(4)
                // fb(6) = (int)l xor key(3)
                LABEL(L["L1"])
                LLOAD(1)
                L2I
                ILOAD(3)
                IXOR
                ISTORE(6)
                // i(5) = 0
                LABEL(L["L2"])
                ICONST_0
                ISTORE(5)
                LABEL(L["L3"])
                FRAME(Opcodes.F_APPEND, 3, arrayOf(Opcodes.INTEGER, Opcodes.INTEGER, Opcodes.INTEGER), 0, null)
                ILOAD(5)
                ALOAD(0)
                ARRAYLENGTH
                IF_ICMPGE(L["L4"])
                // mask(7) = rol(n,i) xor (int)l xor fb ; rol(n,i) = (n<<i) | (n>>>-i)
                LABEL(L["L5"])
                ILOAD(4)
                ILOAD(5)
                ISHL
                ILOAD(4)
                ILOAD(5)
                INEG
                IUSHR
                IOR
                LLOAD(1)
                L2I
                IXOR
                ILOAD(6)
                IXOR
                ISTORE(7)
                // cc = arr[i] (this is still ciphertext here); fb = cc; arr[i] = cc xor mask
                LABEL(L["L6"])
                ALOAD(0)
                ILOAD(5)
                ALOAD(0)
                ILOAD(5)
                CALOAD
                DUP
                ISTORE(6)
                ILOAD(7)
                IXOR
                I2C
                CASTORE
                // n += i + 1
                LABEL(L["L7"])
                ILOAD(4)
                ILOAD(5)
                IADD
                ICONST_1
                IADD
                ISTORE(4)
                LABEL(L["L8"])
                IINC(5, 1)
                GOTO(L["L3"])
                LABEL(L["L4"])
                FRAME(Opcodes.F_CHOP, 1, null, 0, null)
                NEW("java/lang/String")
                DUP
                ALOAD(0)
                INVOKESPECIAL("java/lang/String", "<init>", "([C)V")
                ARETURN
                LABEL(L["L9"])
            }
            MAXS(6, 8)
        }
    }

    /**
     * Variant D: modular multiplication is the main transform instead of XOR.
     * `odd` (always odd, so invertible mod 2^16) is picked per-string at build
     * time; its modular inverse is computed once in Kotlin (BigInteger) and is
     * what actually gets passed as the runtime int argument - the decrypt
     * method only ever multiplies by the inverse, it never has to compute one.
     */
    private object VariantD : Variant() {
        override fun encrypt(cArray: CharArray, seed: Long, key: Int, classKey: Int): Pair<String, Int> {
            var odd = key or 1
            if (odd == 0) odd = 1
            val odd16 = odd and 0xFFFF
            val inv = java.math.BigInteger.valueOf(odd16.toLong())
                .modInverse(java.math.BigInteger.valueOf(65536L))
                .toInt()
            val out = CharArray(cArray.size)
            for (i in cArray.indices) {
                val xmask = i * GOLDEN + seed.toInt() + classKey
                val tmp = cArray[i].code xor xmask
                out[i] = ((tmp and 0xFFFF) * odd16).toChar()
            }
            return String(out) to inv
        }

        override fun createDecryptMethod(classNode: ClassNode, methodName: String, classKey: Int): MethodNode = method(
            (if (classNode.isInterface) PUBLIC else PRIVATE) + STATIC,
            methodName,
            "([CJI)Ljava/lang/String;"
        ) {
            INSTRUCTIONS {
                // i(4) = 0
                LABEL(L["L0"])
                ICONST_0
                ISTORE(4)
                LABEL(L["L1"])
                FRAME(Opcodes.F_APPEND, 1, arrayOf(Opcodes.INTEGER), 0, null)
                ILOAD(4)
                ALOAD(0)
                ARRAYLENGTH
                IF_ICMPGE(L["L2"])
                // xmask(5) = i*GOLDEN + (int)l + classKey
                LABEL(L["L3"])
                ILOAD(4)
                INT(GOLDEN)
                IMUL
                LLOAD(1)
                L2I
                IADD
                INT(classKey)
                IADD
                ISTORE(5)
                // arr[i] = (char)((arr[i] * invOdd(3)) xor xmask)
                LABEL(L["L4"])
                ALOAD(0)
                ILOAD(4)
                ALOAD(0)
                ILOAD(4)
                CALOAD
                ILOAD(3)
                IMUL
                ILOAD(5)
                IXOR
                I2C
                CASTORE
                LABEL(L["L5"])
                IINC(4, 1)
                GOTO(L["L1"])
                LABEL(L["L2"])
                FRAME(Opcodes.F_CHOP, 1, null, 0, null)
                NEW("java/lang/String")
                DUP
                ALOAD(0)
                INVOKESPECIAL("java/lang/String", "<init>", "([C)V")
                ARETURN
                LABEL(L["L6"])
            }
            MAXS(5, 6)
        }
    }

    private val variants: List<Variant> = listOf(VariantA, VariantB, VariantC, VariantD)

    private fun pickVariant(): Variant = variants[Random.nextInt(variants.size)]

    private val String.reflectionExcluded
        get() = ReflectionSupportTransformer.enabled && ReflectionSupportTransformer.strBlacklist.contains(this)

    override fun ResourceCache.transform() {
        Logger.info(" - Encrypting strings...")

        // Diagnostics: figure out exactly where the count drops to zero if it does.
        val totalClasses = nonExcluded.size
        val eligibleClasses = nonExcluded.count { c -> c.version > Opcodes.V1_5 && exclusion.none { c.name.startsWith(it) } }
        val totalLdcStringsFound = nonExcluded
            .filter { c -> c.version > Opcodes.V1_5 && exclusion.none { c.name.startsWith(it) } }
            .sumOf { c -> c.methods.sumOf { m -> m.instructions.count { it is LdcInsnNode && it.cst is String } } }
        Logger.info("    [Diag] nonExcluded classes: $totalClasses, eligible (version+exclusion filter): $eligibleClasses, raw LDC string instructions found: $totalLdcStringsFound")

        val count = count {
            runBlocking {
                nonExcluded.asSequence()
                    .filter { c -> c.version > Opcodes.V1_5 && exclusion.none { c.name.startsWith(it) }
                    }.forEach { classNode ->
                        fun job() {
                            transformClass(classNode, null)
                        }
                        if (Configs.Settings.parallel) launch(Dispatchers.Default) { job() } else job()
                    }
            }
        }.get()
        Logger.info("    Encrypted $count strings")
    }

    override fun transformMethod(owner: ClassNode, method: MethodNode) {
        transformClass(owner, method)
    }

    private fun transformClass(classNode: ClassNode, onlyObfuscate: MethodNode?) {
        val stringsToEncrypt = mutableMapOf<String, Int>()
        val classKey = Random.nextInt()

        // First, replace all INVOKEDYNAMIC instructions with LDC instructions.
        if (replaceInvokeDynamics) {
            replaceInvokeDynamics(classNode, onlyObfuscate)
        }

        // Then, go over all LDC instructions and collect them.
        classNode.methods.shuffled().forEach { methodNode ->
            if (onlyObfuscate != null && onlyObfuscate != methodNode) return@forEach
            methodNode.instructions.asSequence()
                .filter { it is LdcInsnNode && it.cst is String }
                .shuffled()
                .forEach { instruction ->
                    val originalString = (instruction as LdcInsnNode).cst as String
                    // Skip duplicate strings
                    val existingIndex = stringsToEncrypt[originalString]
                    stringsToEncrypt.putIfAbsent(originalString, existingIndex ?: stringsToEncrypt.size)
                }
        }

        if (stringsToEncrypt.isNotEmpty()) {
            // Technique B: no shared field/array/init-method for this class at
            // all - every string is decrypted inline at its own LDC site with
            // its own seed/key. Chosen randomly per class so not every class
            // in the jar has the same "pool field + init method" fingerprint.
            val variant = pickVariant()
            val useInline = stringsToEncrypt.size <= inlineMaxStrings && Random.nextInt(100) < inlineChance
            if (useInline) {
                encryptInline(classNode, onlyObfuscate, classKey, variant)
                return
            }

            val poolField = field(
                (if (classNode.isInterface) PUBLIC + FINAL else PRIVATE) + STATIC,
                getRandomString(16),
                "[Ljava/lang/String;",
                null, null)
            val decryptMethod = variant.createDecryptMethod(classNode, getRandomString(16), classKey)
            val encryptedStrings = stringsToEncrypt.keys.map { it }.toTypedArray()
            val arrayInitMethod = method(
                (if (classNode.isInterface) PUBLIC else PRIVATE) + STATIC,
                getRandomString(16),
                "()V") {
                INSTRUCTIONS {
                    encryptedStrings.forEachIndexed { index, string ->
                        val key = Random.nextInt()
                        val seed = Random.nextLong(100000L)
                        val (encrypted, runtimeKey) = variant.encrypt(string.toCharArray(), seed, key, classKey)
                        GETSTATIC(classNode.name, poolField.name, poolField.desc)
                        INT(index)
                        if (arrayed) {
                            INT(encrypted.length)
                            NEWARRAY(Opcodes.T_CHAR)
                            for (i in 0..(encrypted.length - 1)) {
                                DUP
                                INT(i)
                                INT(encrypted[i].code)
                                CASTORE
                            }
                        } else {
                            LDC(encrypted)
                            INVOKEVIRTUAL("java/lang/String", "toCharArray", "()[C", false)
                        }
                        LONG(seed)
                        INT(runtimeKey)
                        INVOKESTATIC(classNode.name, decryptMethod.name, decryptMethod.desc, classNode.isInterface)
                        AASTORE
                    }
                    RETURN
                }
                MAXS(3, 0)
            }

            (classNode.methods.find { it.name == "<clinit>" } ?: clinit().also {
                it.instructions.insert(InsnNode(Opcodes.RETURN))
                classNode.methods.add(it)
            }).instructions.insert(instructions {
                INT(encryptedStrings.size)
                ANEWARRAY("java/lang/String")
                PUTSTATIC(classNode.name, poolField.name, poolField.desc)
                INVOKESTATIC(classNode.name, arrayInitMethod.name, arrayInitMethod.desc, classNode.isInterface)
            })

            classNode.methods.forEach { methodNode ->
                if (onlyObfuscate != null && onlyObfuscate != methodNode) return@forEach
                methodNode.instructions.asSequence()
                    .filter { it is LdcInsnNode && it.cst is String }
                    .shuffled()
                    .forEach { instruction ->
                        val originalString = (instruction as LdcInsnNode).cst as String
                        val index = stringsToEncrypt[originalString]!!
                        methodNode.instructions.insert(instruction, instructions {
                            GETSTATIC(classNode.name, poolField.name, poolField.desc)
                            INT(index)
                            AALOAD
                        })
                        methodNode.instructions.remove(instruction)
                    }
            }

            classNode.fields.add(poolField)
            classNode.methods.add(decryptMethod)
            classNode.methods.add(arrayInitMethod)
        }
    }

    /**
     * Technique B (no pool field): decrypts every string LDC in [classNode]
     * right at its own call-site, each with an independently random seed/key.
     * No `[Ljava/lang/String;` field, no `<clinit>` write, no array-init
     * method is added to the class - only the shared [decryptMethod].
     */
    private fun encryptInline(classNode: ClassNode, onlyObfuscate: MethodNode?, classKey: Int, variant: Variant) {
        val decryptMethod = variant.createDecryptMethod(classNode, getRandomString(16), classKey)

        classNode.methods.forEach { methodNode ->
            if (onlyObfuscate != null && onlyObfuscate != methodNode) return@forEach
            methodNode.instructions.asSequence()
                .filter { it is LdcInsnNode && it.cst is String }
                .shuffled()
                .forEach { instruction ->
                    val originalString = (instruction as LdcInsnNode).cst as String
                    val key = Random.nextInt()
                    val seed = Random.nextLong(100000L)
                    val (encrypted, runtimeKey) = variant.encrypt(originalString.toCharArray(), seed, key, classKey)
                    methodNode.instructions.insert(instruction, instructions {
                        if (arrayed) {
                            INT(encrypted.length)
                            NEWARRAY(Opcodes.T_CHAR)
                            for (i in encrypted.indices) {
                                DUP
                                INT(i)
                                INT(encrypted[i].code)
                                CASTORE
                            }
                        } else {
                            LDC(encrypted)
                            INVOKEVIRTUAL("java/lang/String", "toCharArray", "()[C", false)
                        }
                        LONG(seed)
                        INT(runtimeKey)
                        INVOKESTATIC(classNode.name, decryptMethod.name, decryptMethod.desc, classNode.isInterface)
                    })
                    methodNode.instructions.remove(instruction)
                }
        }

        classNode.methods.add(decryptMethod)
    }

    // https://github.com/yaskylan/GotoObfuscator/blob/master/src/main/java/org/g0to/transformer/features/stringencryption/
    fun replaceInvokeDynamics(classNode: ClassNode, onlyObfuscate: MethodNode?) {
        val invokeDynamicConcatMethods = ArrayList<MethodNode>()

        classNode.methods.forEach { methodNode ->
            if (onlyObfuscate != null && onlyObfuscate != methodNode) return@forEach
            methodNode.instructions.asSequence()
                .filter { it is InvokeDynamicInsnNode && isStringConcatenation(it) }
                .shuffled()
                .forEach { instruction ->
                    try {
                        invokeDynamicConcatMethods.add(processStringConcatenation(
                            classNode,
                            methodNode,
                            instruction as InvokeDynamicInsnNode,
                            getRandomString(16)
                        ))
                    } catch (e: Exception) {
                        // Some makeConcatWithConstants recipes (e.g. containing raw \u0002
                        // constants that don't line up with bsmArgs, or other edge-case
                        // encodings) can't be safely rewritten. Skip just this instruction
                        // instead of failing the whole obfuscation run.
                        Logger.warn(
                            "  [StringEncrypt] Skipped one invokedynamic string concat in " +
                                    "${classNode.name}.${methodNode.name}${methodNode.desc} " +
                                    "(${e.javaClass.simpleName}: ${e.message})"
                        )
                    }
                }
        }

        invokeDynamicConcatMethods.forEach {
            classNode.methods.add(it)
        }
    }

    fun isStringConcatenation(instruction: InvokeDynamicInsnNode): Boolean {
        return instruction.name.equals("makeConcatWithConstants")
                && instruction.bsmArgs[0].toString().find { it != '\u0001' } != null
    }

    fun processStringConcatenation(classNode: ClassNode, methodNode: MethodNode,
                                   instruction: InvokeDynamicInsnNode, bootstrapName: String): MethodNode {
        val arg = instruction.bsmArgs[0].toString()
        val argString = StringBuilder()
        val newArg = StringBuilder()
        val constants = ArrayList<String>()

        fun flushArgs() {
            if (argString.isNotEmpty()) {
                constants.add(argString.toString())
                argString.setLength(0)
                newArg.append('\u0002')
            }
        }

        var bsmArgIndex = 1

        for (c in arg) {
            when (c) {
                '\u0001' -> {
                    flushArgs()
                    newArg.append('\u0001')
                }
                '\u0002' -> {
                    flushArgs()
                    if (bsmArgIndex >= instruction.bsmArgs.size) {
                        // Recipe references a constant bsm argument that doesn't exist.
                        // This happens for some javac-generated concat recipes (e.g. the
                        // literal string content itself containing a \u0002 control char)
                        // that don't map 1:1 onto extra bootstrap constants. Bail out
                        // cleanly instead of letting the array access throw AIOOBE.
                        throw IllegalStateException(
                            "bsmArgs index $bsmArgIndex out of bounds (size ${instruction.bsmArgs.size}) " +
                                    "for recipe \"$arg\" in ${classNode.name}.${methodNode.name}${methodNode.desc}"
                        )
                    }
                    constants.add(instruction.bsmArgs[bsmArgIndex++].toString())
                    newArg.append('\u0002')
                }
                else -> {
                    argString.append(c)
                }
            }
        }

        flushArgs()

        if (constants.isEmpty()) {
            throw IllegalStateException()
        }

        val bootstrap = createConcatBootstrap(classNode, bootstrapName, constants)

        methodNode.instructions.insert(instruction, instructions {
            INVOKEDYNAMIC(
                instruction.name,
                instruction.desc,
                Handle(
                    Opcodes.H_INVOKESTATIC,
                    classNode.name,
                    bootstrap.name,
                    bootstrap.desc,
                    classNode.isInterface
                ),
                newArg.toString()
            )
        })
        methodNode.instructions.remove(instruction)
        return bootstrap
    }

    private fun createConcatBootstrap(classNode: ClassNode, methodName: String, constants: ArrayList<String>) = method(
            (if (classNode.isInterface) PUBLIC else PRIVATE) + STATIC,
            methodName,
            "(Ljava/lang/invoke/MethodHandles\$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;Ljava/lang/String;)Ljava/lang/invoke/CallSite;") {
        INSTRUCTIONS {
            ALOAD(0)
            ALOAD(1)
            ALOAD(2)
            ALOAD(3)
            INT(constants.size)
            ANEWARRAY("java/lang/Object")
            DUP

            for ((i, cst) in constants.withIndex()) {
                INT(i)
                LDC(cst)
                AASTORE
                if (i != constants.lastIndex) {
                    DUP
                }
            }

            INVOKESTATIC(
                "java/lang/invoke/StringConcatFactory",
                "makeConcatWithConstants",
                "(Ljava/lang/invoke/MethodHandles\$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/invoke/CallSite;")
            ARETURN
        }
        MAXS(8, 4)
    }

    fun createDecryptMethod(classNode: ClassNode, methodName: String, classKey: Int): MethodNode = method(
        (if (classNode.isInterface) PUBLIC else PRIVATE) + STATIC,
        methodName,
        "([CJI)Ljava/lang/String;"
    ) {
        INSTRUCTIONS {
            LABEL(L["L0"])
            INT(classKey)
            ILOAD(3)
            IXOR
            ISTORE(4)
            LABEL(L["L1"])
            ICONST_0
            ISTORE(5)
            LABEL(L["L2"])
            FRAME(Opcodes.F_APPEND, 2, arrayOf(Opcodes.INTEGER, Opcodes.INTEGER), 0, null)
            ILOAD(5)
            ALOAD(0)
            ARRAYLENGTH
            IF_ICMPGE(L["L3"])
            LABEL(L["L4"])
            ILOAD(4)
            LLOAD(1)
            L2I
            IXOR
            ILOAD(5)
            ICONST_M1
            IXOR
            IXOR
            ISTORE(4)
            LABEL(L["L5"])
            ILOAD(4)
            ILOAD(3)
            ILOAD(5)
            ALOAD(0)
            ARRAYLENGTH
            IMUL
            ISUB
            IXOR
            ISTORE(4)
            LABEL(L["L6"])
            ILOAD(4)
            INEG
            ILOAD(3)
            IMUL
            ILOAD(5)
            IOR
            ISTORE(4)
            LABEL(L["L7"])
            ALOAD(0)
            ILOAD(5)
            ALOAD(0)
            ILOAD(5)
            CALOAD
            ILOAD(4)
            IXOR
            I2C
            CASTORE
            LABEL(L["L8"])
            ILOAD(5)
            SIPUSH(255)
            IAND
            ISTORE(6)
            LABEL(L["L9"])
            ILOAD(3)
            ILOAD(6)
            ISHL
            ILOAD(3)
            ILOAD(6)
            INEG
            IUSHR
            IOR
            ISTORE(3)
            LABEL(L["L10"])
            LLOAD(1)
            ILOAD(6)
            I2L
            LXOR
            LSTORE(1)
            LABEL(L["L11"])
            IINC(5, 1)
            GOTO(L["L2"])
            LABEL(L["L3"])
            FRAME(Opcodes.F_CHOP, 1, null, 0, null)
            NEW("java/lang/String")
            DUP
            ALOAD(0)
            INVOKESPECIAL("java/lang/String", "<init>", "([C)V")
            ARETURN
            LABEL(L["L12"])
        }
        MAXS(4, 7)
    }

    fun encrypt(cArray: CharArray, seed: Long, key: Int, classKey: Int): String {
        var n = key
        var l = seed
        var n2 = classKey xor n

        for (i in cArray.indices) {
            n2 = n2 xor l.toInt() xor i.inv()
            n2 = n2 xor (n - i * cArray.size)
            n2 = (-n2 * n) or i
            cArray[i] = (cArray[i].code xor n2).toChar()
            val n3 = i and 0xFF
            n = (n shl n3) or (n ushr -n3)
            l = l xor n3.toLong()
        }
        return String(cArray)
    }
}