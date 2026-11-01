package net.spartanb312.grunt.process.transformers.flow

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import net.spartanb312.genesis.kotlin.instructions
import net.spartanb312.grunt.annotation.DISABLE_CONTROLFLOW
import net.spartanb312.grunt.config.Configs
import net.spartanb312.grunt.config.setting
import net.spartanb312.grunt.process.MethodProcessor
import net.spartanb312.grunt.process.Transformer
import net.spartanb312.grunt.process.hierarchy.Hierarchy
import net.spartanb312.grunt.process.hierarchy.ReferenceSearch
import net.spartanb312.grunt.process.resource.ResourceCache
import net.spartanb312.grunt.process.transformers.flow.process.*
import net.spartanb312.grunt.utils.count
import net.spartanb312.grunt.utils.extensions.hasAnnotation
import net.spartanb312.grunt.utils.extensions.isDummy
import net.spartanb312.grunt.utils.logging.Logger
import net.spartanb312.grunt.utils.notInList
import org.objectweb.asm.Opcodes
import org.objectweb.asm.Type
import org.objectweb.asm.tree.*
import kotlin.random.Random

/**
 * Obfuscating the controlflow
 * Last update on 24/12/24
 */
object ControlflowTransformer : Transformer("Controlflow", Category.Controlflow), MethodProcessor {

    private val intensity by setting("Intensity", 1)  // Range 1..3
    private var beforeEncrypt by setting("ExecuteBeforeEncrypt", false)
    private val switchExtractor by setting("SwitchExtractor", true) // Author: jonesdevelopment
    private val extractRate by setting("ExtractRate", 30) // Range 0..100
    private val bogusJump by setting("BogusConditionJump", true)
    private val gotoRate by setting("GotoReplaceRate", 80) // Range 0..100
    private val mangledIf by setting("MangledCompareJump", true)
    private val ifRate by setting("IfReplaceRate", 50) // Range 0..100
    private val ifCompareRate by setting("IfICompareReplaceRate", 100) // Range 0..100
    private val switchProtect by setting("SwitchProtect", true)
    private val protectRate by setting("ProtectRate", 30) // Range 0..100
    private val tableSwitch by setting("TableSwitchJump", true)
    // Ported from Skidfuscator's BasicRangeTransformer idea: route a GOTO through
    // a throw/catch pair instead of jumping directly (see process/ExceptionGoto.kt)
    private val exceptionJump by setting("ExceptionGotoJump", false) // tạm tắt, step7 chèn try-catch đè lên GOTO nằm trong try-catch có sẵn -> exception table hỏng
    private val exceptionRate by setting("ExceptionGotoRate", 15) // Range 0..100
    private val mutateJumps by setting("MutateJumps", true)
    private val mutateRate by setting("MutateRate", 10) // Range 0..100
    private val switchRate by setting("SwitchReplaceRate", 30)  // Range 0..100
    private val maxSwitchCase by setting("MaxSwitchCase", 5) // Range 1..10
    val reverseExistedIf by setting("ReverseExistedIf", true)
    val reverseChance by setting("ReverseChance", 50) // Range 0..100
    val trappedCase by setting("TrappedSwitchCase", true)
    val trapChance by setting("TrapChance", 50) // Range 0..100
    var arithmeticExpr by setting("ArithmeticExprBuilder", true)
    val asIntensity by setting("BuilderIntensity", 1) // Range 1..3
    val junkParameter by setting("JunkBuilderParameter", true)
    val annotationOnBuilder by setting("BuilderNativeAnnotation", false)
    val useLocalVar by setting("UseLocalVar", true)
    var junkCode by setting("JunkCode", true)
    private var _maxJunkCode by setting("MaxJunkCode", 2)  // Range 1..5
    var maxJunkCode: Int
        get() = _maxJunkCode.coerceAtLeast(1)
        set(value) {
            _maxJunkCode = value.coerceAtLeast(1)
        }
    val expandedJunkCode by setting("ExpandedJunkCode", true)
    val exclusion by setting("Exclusion", listOf())
    val maxDegradeAttempts by setting("MaxDegradeAttempts", 5)
    val skipIfStillOversized by setting("SkipIfStillOversized", true)
    val intensityOverrides by setting("IntensityOverrides", com.google.gson.JsonObject())
    var autoDisabledMethods by setting("AutoDisabledMethods", listOf<String>())

    data class FlowSettings(
        val intensity: Int,
        val switchProtect: Boolean,
        val protectRate: Int,
        val mutateJumps: Boolean,
        val mutateRate: Int,
        val switchExtractor: Boolean,
        val extractRate: Int,
        val bogusJump: Boolean,
        val gotoRate: Int,
        val mangledIf: Boolean,
        val ifRate: Int,
        val ifCompareRate: Int,
        val tableSwitch: Boolean,
        val switchRate: Int,
        val maxSwitchCase: Int,
        val junkCode: Boolean,
        val maxJunkCode: Int,
        val arithmeticExpr: Boolean,
        val exceptionJump: Boolean,
        val exceptionRate: Int,
        val stage: Int = 0
    ) {
        // Mỗi lần gọi degrade() chỉ lùi ĐÚNG 1 bước, theo thứ tự ưu tiên:
        // kỹ thuật rẻ tiền/ít giá trị bảo vệ bị giảm rate hoặc tắt TRƯỚC,
        // kỹ thuật mạnh (MangledCompareJump, ArithmeticExprBuilder, SwitchProtect)
        // được giữ nguyên LÂU NHẤT. Ưu tiên "chèn ít lại" (giảm rate) trước khi
        // tắt hẳn (false), thay vì tắt luôn một lượt.
        fun degrade(): FlowSettings {
            var step = stage
            while (step < 13) {
                val next = applyStage(step)
                step++
                if (next != this) return next.copy(stage = step)
            }
            return copy(stage = step) // hết bài, không còn gì rẻ hơn để cắt
        }

        private fun applyStage(step: Int): FlowSettings = when (step) {
            0 -> if (junkCode || maxJunkCode > 0) copy(junkCode = false, maxJunkCode = 0) else this
            1 -> if (exceptionJump || exceptionRate > 0) copy(exceptionJump = false, exceptionRate = 0) else this
            2 -> if (mutateRate > 10) copy(mutateRate = (mutateRate / 2).coerceAtLeast(10))
                 else if (mutateJumps) copy(mutateJumps = false) else this
            3 -> if (tableSwitch) copy(tableSwitch = false) else this
            4 -> if (gotoRate > 10) copy(gotoRate = (gotoRate / 2).coerceAtLeast(10)) else this
            5 -> if (switchRate > 5 || maxSwitchCase > 1) copy(
                     switchRate = (switchRate / 2).coerceAtLeast(5),
                     maxSwitchCase = (maxSwitchCase / 2).coerceAtLeast(1)
                 ) else this
            6 -> if (ifRate > 10 || ifCompareRate > 10) copy(
                     ifRate = (ifRate / 2).coerceAtLeast(10),
                     ifCompareRate = (ifCompareRate / 2).coerceAtLeast(10)
                 ) else this
            7 -> if (bogusJump) copy(bogusJump = false) else this
            8 -> if (extractRate > 10) copy(extractRate = (extractRate / 2).coerceAtLeast(10))
                 else if (switchExtractor) copy(switchExtractor = false) else this
            9 -> if (protectRate > 5) copy(protectRate = (protectRate / 2).coerceAtLeast(5))
                 else if (switchProtect) copy(switchProtect = false) else this
            10 -> if (mangledIf) copy(mangledIf = false) else this
            11 -> if (arithmeticExpr) copy(arithmeticExpr = false) else this
            12 -> if (intensity > 1) copy(intensity = intensity - 1) else this
            else -> this
        }
    }

    private fun getEffectiveSettings(className: String, methodKey: String = ""): FlowSettings {
        var effIntensity = intensity
        var effSwitchProtect = switchProtect
        var effProtectRate = protectRate
        var effMutateJumps = mutateJumps
        var effMutateRate = mutateRate
        var effSwitchExtractor = switchExtractor
        var effExtractRate = extractRate
        var effBogusJump = bogusJump
        var effGotoRate = gotoRate
        var effMangledIf = mangledIf
        var effIfRate = ifRate
        var effIfCompareRate = ifCompareRate
        var effTableSwitch = tableSwitch
        var effSwitchRate = switchRate
        var effMaxSwitchCase = maxSwitchCase
        var effJunkCode = junkCode
        var effMaxJunkCode = maxJunkCode
        var effArithmeticExpr = arithmeticExpr
        var effExceptionJump = exceptionJump
        var effExceptionRate = exceptionRate

        try {
            for ((pattern, element) in intensityOverrides.entrySet()) {
                val matched = matchesPattern(className, pattern) ||
                        (methodKey.isNotEmpty() && matchesPattern(methodKey, pattern))
                if (matched && element.isJsonObject) {
                    val obj = element.asJsonObject
                    if (obj.has("Intensity")) effIntensity = obj.get("Intensity").asInt
                    if (obj.has("SwitchProtect")) effSwitchProtect = obj.get("SwitchProtect").asBoolean
                    if (obj.has("ProtectRate")) effProtectRate = obj.get("ProtectRate").asInt
                    if (obj.has("MutateJumps")) effMutateJumps = obj.get("MutateJumps").asBoolean
                    if (obj.has("MutateRate")) effMutateRate = obj.get("MutateRate").asInt
                    if (obj.has("SwitchExtractor")) effSwitchExtractor = obj.get("SwitchExtractor").asBoolean
                    if (obj.has("ExtractRate")) effExtractRate = obj.get("ExtractRate").asInt
                    if (obj.has("BogusConditionJump")) effBogusJump = obj.get("BogusConditionJump").asBoolean
                    if (obj.has("GotoReplaceRate")) effGotoRate = obj.get("GotoReplaceRate").asInt
                    if (obj.has("MangledCompareJump")) effMangledIf = obj.get("MangledCompareJump").asBoolean
                    if (obj.has("IfReplaceRate")) effIfRate = obj.get("IfReplaceRate").asInt
                    if (obj.has("IfICompareReplaceRate")) effIfCompareRate = obj.get("IfICompareReplaceRate").asInt
                    if (obj.has("TableSwitchJump")) effTableSwitch = obj.get("TableSwitchJump").asBoolean
                    if (obj.has("SwitchReplaceRate")) effSwitchRate = obj.get("SwitchReplaceRate").asInt
                    if (obj.has("MaxSwitchCase")) effMaxSwitchCase = obj.get("MaxSwitchCase").asInt
                    if (obj.has("JunkCode")) effJunkCode = obj.get("JunkCode").asBoolean
                    if (obj.has("MaxJunkCode")) effMaxJunkCode = obj.get("MaxJunkCode").asInt
                    if (obj.has("ArithmeticExprBuilder")) effArithmeticExpr = obj.get("ArithmeticExprBuilder").asBoolean
                    if (obj.has("ExceptionGotoJump")) effExceptionJump = obj.get("ExceptionGotoJump").asBoolean
                    if (obj.has("ExceptionGotoRate")) effExceptionRate = obj.get("ExceptionGotoRate").asInt
                    break
                }
            }
        } catch (e: Exception) {
            Logger.warn("Failed to parse intensityOverrides: ${e.message}")
        }

        return FlowSettings(
            intensity = effIntensity,
            switchProtect = effSwitchProtect,
            protectRate = effProtectRate,
            mutateJumps = effMutateJumps,
            mutateRate = effMutateRate,
            switchExtractor = effSwitchExtractor,
            extractRate = effExtractRate,
            bogusJump = effBogusJump,
            gotoRate = effGotoRate,
            mangledIf = effMangledIf,
            ifRate = effIfRate,
            ifCompareRate = effIfCompareRate,
            tableSwitch = effTableSwitch,
            switchRate = effSwitchRate,
            maxSwitchCase = effMaxSwitchCase,
            junkCode = effJunkCode,
            maxJunkCode = effMaxJunkCode,
            arithmeticExpr = effArithmeticExpr,
            exceptionJump = effExceptionJump,
            exceptionRate = effExceptionRate
        )
    }

    private fun matchesPattern(text: String, pattern: String): Boolean {
        if (pattern == text || pattern == "*") return true
        val regex = pattern.replace(".", "/")
            .replace("**", ".*")
            .replace("*", "[^/]*")
        return text.replace(".", "/").matches(Regex(regex))
    }

    override var order: Int
        get() = if (beforeEncrypt) 200 else 400
        set(value) {
            beforeEncrypt = value == 200
        }

    // Store pristine method backups before controlflow so we can restore if class dump fails with ClassTooLarge
    val originalMethodBackups = java.util.concurrent.ConcurrentHashMap<String, MethodNode>()
    private val autoDisableLock = Any()
    private val newlyDisabledMethods = java.util.concurrent.ConcurrentLinkedQueue<String>()

    /** Ghi methodKey vào AutoDisabledMethods (persist qua config) để build sau skip luôn không cần test lại. */
    private fun markMethodAutoDisabled(methodKey: String) {
        synchronized(autoDisableLock) {
            if (methodKey !in autoDisabledMethods) {
                autoDisabledMethods = autoDisabledMethods + methodKey
            }
        }
        newlyDisabledMethods.add(methodKey)
    }

    override fun ResourceCache.transform() {
        Logger.info(" - Transforming controlflows...")
        JunkCode.refresh(this)
        ArithmeticExpr.refresh(this)
        val hierarchy = Hierarchy(this)
        hierarchy.build(true)
        val disabledSet = autoDisabledMethods.toHashSet()
        val skippedKnown = java.util.concurrent.atomic.AtomicInteger(0)
        val count = count {
            runBlocking {
                nonExcluded.asSequence()
                    .filter {
                        it.name.notInList(exclusion)
                                && !it.missingReference(hierarchy)
                                && !it.hasAnnotation(DISABLE_CONTROLFLOW)
                    }.forEach { classNode ->
                        fun job() {
                            classNode.methods.toList().forEach { methodNode ->
                                if (!methodNode.hasAnnotation(DISABLE_CONTROLFLOW)) {
                                    val key = "${classNode.name}.${methodNode.name}${methodNode.desc}"
                                    if (key in disabledSet) {
                                        skippedKnown.incrementAndGet()
                                        return@forEach
                                    }
                                    originalMethodBackups[key] = cloneMethodNode(methodNode)
                                    add(processMethodWithDegrade(classNode, methodNode, false))
                                }
                            }
                        }
                        if (Configs.Settings.parallel) launch(Dispatchers.Default) { job() } else job()
                    }
            }
        }
        if (skippedKnown.get() > 0) {
            Logger.info("    Skipped ${skippedKnown.get()} method(s) known to exceed 64KB (AutoDisabledMethods).")
        }
        if (newlyDisabledMethods.isNotEmpty()) {
            Logger.warn("    Permanently disabled ${newlyDisabledMethods.size} method(s) still exceeding 64KB after full degrade.")
            newlyDisabledMethods.clear()
        }
        Logger.info("    Replaced ${count.get()} jumps")
    }

    fun transformMethod(owner: ClassNode, method: MethodNode, indyReobf: Boolean) {
        processMethodWithDegrade(owner, method, indyReobf)
    }

    override fun transformMethod(owner: ClassNode, method: MethodNode) {
        processMethodWithDegrade(owner, method, false)
    }

    private fun cloneMethodNode(src: MethodNode): MethodNode {
        val copy = MethodNode(
            Opcodes.ASM9,
            src.access,
            src.name,
            src.desc,
            src.signature,
            src.exceptions?.toTypedArray()
        )
        src.accept(copy)
        return copy
    }

    private fun restoreMethodNode(target: MethodNode, backup: MethodNode) {
        target.instructions.clear()
        target.tryCatchBlocks?.clear()
        target.localVariables?.clear()
        target.visibleLocalVariableAnnotations?.clear()
        target.invisibleLocalVariableAnnotations?.clear()
        // accept() chỉ append, nên phải reset hết để khỏi bị nhân đôi
        target.visibleAnnotations = null
        target.invisibleAnnotations = null
        target.visibleTypeAnnotations = null
        target.invisibleTypeAnnotations = null
        target.visibleParameterAnnotations = null
        target.invisibleParameterAnnotations = null
        target.parameters = null
        target.attrs = null

        backup.accept(target)
    }

    private fun testMethodSize(owner: ClassNode, methodNode: MethodNode): Boolean {
        return try {
            val cw = org.objectweb.asm.ClassWriter(org.objectweb.asm.ClassWriter.COMPUTE_FRAMES)
            cw.visit(owner.version, owner.access, owner.name, owner.signature, owner.superName, owner.interfaces?.toTypedArray())
            val mv = cw.visitMethod(methodNode.access, methodNode.name, methodNode.desc, methodNode.signature, methodNode.exceptions?.toTypedArray())
            methodNode.accept(mv)
            cw.visitEnd()
            val bytes = cw.toByteArray()
            bytes.isNotEmpty()
        } catch (e: org.objectweb.asm.MethodTooLargeException) {
            false
        } catch (e: org.objectweb.asm.ClassTooLargeException) {
            false
        } catch (e: Exception) {
            val msg = e.message ?: ""
            if (msg.contains("Method code too large") || msg.contains("too large")) {
                false
            } else {
                // If it's a hierarchy error during COMPUTE_FRAMES simulation, fallback to COMPUTE_MAXS
                try {
                    val cwMax = org.objectweb.asm.ClassWriter(org.objectweb.asm.ClassWriter.COMPUTE_MAXS)
                    cwMax.visit(owner.version, owner.access, owner.name, owner.signature, owner.superName, owner.interfaces?.toTypedArray())
                    val mv = cwMax.visitMethod(methodNode.access, methodNode.name, methodNode.desc, methodNode.signature, methodNode.exceptions?.toTypedArray())
                    methodNode.accept(mv)
                    cwMax.visitEnd()
                    cwMax.toByteArray().isNotEmpty()
                } catch (ex: Exception) {
                    val m = ex.message ?: ""
                    !m.contains("too large") && ex !is org.objectweb.asm.MethodTooLargeException && ex !is org.objectweb.asm.ClassTooLargeException
                }
            }
        }
    }


    private fun processMethodWithDegrade(owner: ClassNode, methodNode: MethodNode, indyReobf: Boolean): Int {
        if (methodNode.instructions.size() == 0) return 0

        val methodKey = "${owner.name}.${methodNode.name}${methodNode.desc}"
        val initialBackup = cloneMethodNode(methodNode)
        var currentSettings = getEffectiveSettings(owner.name, methodKey)

        var attempts = 0
        val maxAttempts = maxDegradeAttempts.coerceAtLeast(1)

        while (attempts <= maxAttempts) {
            restoreMethodNode(methodNode, initialBackup)
            val replaced = applyControlflow(owner, methodNode, indyReobf, currentSettings)

            if (testMethodSize(owner, methodNode)) {
                if (attempts > 0) {
                    Logger.warn("Method $methodKey successfully fit within 64KB after $attempts degrade attempt(s).")
                }
                return replaced
            }

            attempts++
            if (attempts <= maxAttempts) {
                Logger.warn("Method $methodKey exceeded 64KB limit! Attempting degrade (#$attempts)...")
                currentSettings = currentSettings.degrade()
            }
        }

        restoreMethodNode(methodNode, initialBackup)
        if (skipIfStillOversized) {
            Logger.error("Method $methodKey still exceeds 64KB after $maxAttempts degrade attempts. Disabling controlflow for this method permanently.")
            markMethodAutoDisabled(methodKey)
        }

        return 0
    }

    /**
     * Called by ResourceCache when a ClassTooLargeException or MethodTooLargeException occurs
     * during the dump phase.
     * @param pass Current retry pass (1, 2, or 3). On pass 3, restores pristine bytecode to guarantee the class fits.
     */
    private fun estimateMethodSize(owner: ClassNode, methodNode: MethodNode): Int {
        return try {
            val cw = org.objectweb.asm.ClassWriter(org.objectweb.asm.ClassWriter.COMPUTE_MAXS)
            cw.visit(owner.version, owner.access, owner.name, owner.signature, owner.superName, owner.interfaces?.toTypedArray())
            val mv = cw.visitMethod(methodNode.access, methodNode.name, methodNode.desc, methodNode.signature, methodNode.exceptions?.toTypedArray())
            methodNode.accept(mv)
            cw.visitEnd()
            cw.toByteArray().size
        } catch (e: Exception) {
            Int.MAX_VALUE // method này lỗi/quá to khi tự dump riêng -> ưu tiên xử lý trước
        }
    }

    fun redegradeClassMethods(classNode: ClassNode, pass: Int = 1) {
        val candidates = classNode.methods.filter { it.instructions.size() > 0 }
        if (candidates.isEmpty()) return

        // Xếp hạng method theo size bytecode thật của chính nó, chỉ đụng vào
        // những method to/phình nhất thay vì degrade đều hết cả class.
        val ranked = candidates
            .map { it to estimateMethodSize(classNode, it) }
            .sortedByDescending { it.second }

        val targetFraction = when (pass) { 1 -> 0.15; 2 -> 0.35; else -> 1.0 }
        val targetCount = if (pass >= 3) ranked.size
            else (ranked.size * targetFraction).toInt().coerceIn(1, ranked.size)
        val targeted = ranked.take(targetCount).map { it.first }.toHashSet()

        Logger.warn("  Re-degrading ${targeted.size}/${ranked.size} method(s) phình nhất của class ${classNode.name} (pass $pass) do class/method quá lớn lúc dump...")

        val extraDegradeSteps = (maxDegradeAttempts + 3).coerceAtLeast(6)
        for (methodNode in classNode.methods) {
            if (methodNode.instructions.size() == 0) continue
            if (methodNode !in targeted) continue // method không phình -> giữ nguyên độ mạnh obfuscate

            // Look up pristine backup if available
            val backup = originalMethodBackups.entries.firstOrNull { 
                it.key.endsWith(".${methodNode.name}${methodNode.desc}") 
            }?.value ?: cloneMethodNode(methodNode)

            val methodKeyForOverride = "${classNode.name}.${methodNode.name}${methodNode.desc}"

            if (pass >= 3) {
                // Last ditch effort: completely restore pristine bytecode for this method
                Logger.warn("  Pass 3: Restoring pristine original bytecode for $methodKeyForOverride to avoid empty class.")
                restoreMethodNode(methodNode, backup)
                markMethodAutoDisabled(methodKeyForOverride)
                continue
            }

            var currentSettings = getEffectiveSettings(classNode.name, methodKeyForOverride)
            // Degrade more aggressively based on pass
            repeat(pass * 2) { currentSettings = currentSettings.degrade() }

            var fit = false
            for (attempt in 0..extraDegradeSteps) {
                restoreMethodNode(methodNode, backup)
                val fullyStripped = currentSettings.gotoRate <= 10 && !currentSettings.junkCode &&
                    !currentSettings.arithmeticExpr && !currentSettings.tableSwitch &&
                    !currentSettings.mutateJumps && !currentSettings.switchExtractor &&
                    !currentSettings.switchProtect && !currentSettings.exceptionJump
                if (fullyStripped && attempt > 0) {
                    restoreMethodNode(methodNode, backup)
                    break
                }
                applyControlflow(classNode, methodNode, false, currentSettings)
                if (testMethodSize(classNode, methodNode)) {
                    fit = true
                    break
                }
                currentSettings = currentSettings.degrade()
            }
            if (!fit) {
                restoreMethodNode(methodNode, backup)
                markMethodAutoDisabled(methodKeyForOverride)
            }
        }
    }

    /**
     * Pinpoint re-degrade: dùng khi ASM biết chính xác method nào bị MethodTooLargeException lúc dump.
     * Chỉ degrade/tắt đúng 1 method này, không đụng các method khác trong class.
     * Trả về false nếu không tìm thấy method (caller nên fallback sang redegradeClassMethods).
     */
    fun redegradeSingleMethod(classNode: ClassNode, methodName: String, methodDesc: String): Boolean {
        val methodNode = classNode.methods.firstOrNull { it.name == methodName && it.desc == methodDesc } ?: return false
        val methodKey = "${classNode.name}.$methodName$methodDesc"
        Logger.warn("  Re-degrading single method $methodKey (pinpointed by MethodTooLargeException)...")

        val backup = originalMethodBackups[methodKey] ?: cloneMethodNode(methodNode)
        var currentSettings = getEffectiveSettings(classNode.name, methodKey)
        val extraDegradeSteps = (maxDegradeAttempts + 5).coerceAtLeast(8)

        var fit = false
        for (attempt in 0..extraDegradeSteps) {
            restoreMethodNode(methodNode, backup)
            applyControlflow(classNode, methodNode, false, currentSettings)
            if (testMethodSize(classNode, methodNode)) {
                fit = true
                break
            }
            currentSettings = currentSettings.degrade()
        }

        if (!fit) {
            restoreMethodNode(methodNode, backup)
            markMethodAutoDisabled(methodKey)
            Logger.error("  Method $methodKey still too large after exhaustive degrade. Disabled permanently (pristine bytecode restored).")
        } else {
            Logger.warn("  Method $methodKey fit within 64KB after targeted re-degrade.")
        }
        return true
    }

    private fun applyControlflow(
        owner: ClassNode,
        methodNode: MethodNode,
        indyReobf: Boolean,
        cfg: FlowSettings
    ): Int {
        var count = 0
        val originalArithmeticExpr = arithmeticExpr
        val originalJunkCode = junkCode
        val originalMaxJunkCode = maxJunkCode

        try {
            arithmeticExpr = cfg.arithmeticExpr
            junkCode = cfg.junkCode
            maxJunkCode = cfg.maxJunkCode

            repeat(cfg.intensity) {
                if (cfg.switchProtect) {
                    val newInsn = instructions { // step1: replace switches
                        methodNode.instructions.forEach { insnNode ->
                            if (Random.nextInt(0, 100) <= cfg.protectRate) {
                                if (!insnNode.previous.isDummy) when (insnNode) {
                                    is LookupSwitchInsnNode -> +LookUpSwitch.generate(insnNode)
                                    is TableSwitchInsnNode -> +LookUpSwitch.generate(insnNode)
                                    else -> +insnNode
                                } else +insnNode
                            } else +insnNode
                        }
                    }
                    methodNode.instructions = newInsn
                }
                if (cfg.mutateJumps) { // step2: replace jumps with table switches
                    methodNode.instructions = instructions {
                        methodNode.instructions.forEach { instruction ->
                            if (instruction is JumpInsnNode
                                && instruction.opcode != Opcodes.GOTO
                                && !instruction.previous.isDummy
                                && Random.nextInt(0, 100) <= cfg.mutateRate
                            ) {
                                +MutateJumps.generate(instruction)
                                count++
                            } else +instruction
                        }
                    }
                }
                if (cfg.switchExtractor) { // step3: extract switches
                    val newInsn = instructions {
                        methodNode.instructions.forEach { insnNode ->
                            if (Random.nextInt(0, 100) <= cfg.extractRate) {
                                if ((insnNode is TableSwitchInsnNode || insnNode is LookupSwitchInsnNode) && !insnNode.previous.isDummy) {
                                    +SwitchExtractor.generate(
                                        insnNode,
                                        methodNode.maxLocals++
                                    )
                                    count++
                                } else +insnNode
                            } else +insnNode
                        }
                    }
                    methodNode.instructions = newInsn
                }
                if (cfg.bogusJump) { // step4: replace goto
                    val newInsn = instructions {
                        val returnType = Type.getReturnType(methodNode.desc)
                        methodNode.instructions.forEach { insnNode ->
                            if (insnNode is JumpInsnNode && insnNode.opcode == Opcodes.GOTO && !insnNode.previous.isDummy
                                && Random.nextInt(0, 100) <= cfg.gotoRate
                            ) {
                                +ReplaceGoto.generate(
                                    insnNode.label,
                                    owner,
                                    methodNode,
                                    returnType,
                                    Random.nextBoolean(),
                                    indyReobf
                                )
                                count++
                            } else +insnNode
                        }
                    }
                    methodNode.instructions = newInsn
                }
                if (cfg.mangledIf) { // step5: process if opcode
                    val newInsn = instructions {
                        val returnType = Type.getReturnType(methodNode.desc)
                        methodNode.instructions.forEach { insnNode ->
                            if (insnNode is JumpInsnNode) {
                                val replaceIf = ReplaceIf.ifOpcodes.any { it == insnNode.opcode }
                                        && Random.nextInt(0, 100) <= cfg.ifRate
                                val replaceCompare = ReplaceIf.ifCompareOpcodes.any { it == insnNode.opcode }
                                        && Random.nextInt(0, 100) <= cfg.ifCompareRate
                                if (replaceIf || replaceCompare) {
                                    +ReplaceIf.generate(
                                        insnNode,
                                        insnNode.label,
                                        owner,
                                        methodNode,
                                        returnType,
                                        Random.nextBoolean(),
                                        indyReobf
                                    )
                                    count++
                                } else +insnNode
                            } else +insnNode
                        }
                    }
                    methodNode.instructions = newInsn
                }
                if (cfg.tableSwitch) { // step6: replace goto to switch
                    val newInsn = instructions {
                        val range = 1..cfg.maxSwitchCase.coerceAtLeast(1)
                        val returnType = Type.getReturnType(methodNode.desc)
                        methodNode.instructions.forEach { insnNode ->
                            if (insnNode is JumpInsnNode && insnNode.opcode == Opcodes.GOTO && !insnNode.previous.isDummy
                                && Random.nextInt(0, 100) <= cfg.switchRate
                            ) {
                                +TableSwitch.generate(
                                    insnNode.label,
                                    owner,
                                    methodNode,
                                    returnType,
                                    range.random(),
                                    Random.nextBoolean(),
                                    indyReobf
                                )
                                count++
                            } else +insnNode
                        }
                    }
                    methodNode.instructions = newInsn
                }
                if (cfg.exceptionJump) { // step7: route remaining goto through throw/catch
                    val newInsn = instructions {
                        methodNode.instructions.forEach { insnNode ->
                            if (insnNode is JumpInsnNode && insnNode.opcode == Opcodes.GOTO && !insnNode.previous.isDummy
                                && Random.nextInt(0, 100) <= cfg.exceptionRate
                            ) {
                                +ExceptionGoto.generate(insnNode.label, methodNode)
                                count++
                            } else +insnNode
                        }
                    }
                    methodNode.instructions = newInsn
                }
            }
            if (cfg.tableSwitch) methodNode.maxLocals += 5
            else if ((cfg.mangledIf || cfg.bogusJump) && useLocalVar) methodNode.maxLocals += 1
        } finally {
            arithmeticExpr = originalArithmeticExpr
            junkCode = originalJunkCode
            maxJunkCode = originalMaxJunkCode
        }

        return count
    }

    private fun ClassNode.missingReference(hierarchy: Hierarchy): Boolean {
        if (hierarchy.getClassInfo(this).missingDependencies) return true
        return ReferenceSearch.checkMissing(this, hierarchy).isNotEmpty()
    }

}