package net.spartanb312.grunt.process.transformers.rename

import net.spartanb312.grunt.config.setting
import net.spartanb312.grunt.process.Transformer
import net.spartanb312.grunt.process.resource.NameGenerator
import net.spartanb312.grunt.process.resource.ResourceCache
import net.spartanb312.grunt.utils.count
import net.spartanb312.grunt.utils.logging.Logger
import net.spartanb312.grunt.utils.notInList
import org.objectweb.asm.Type
import org.objectweb.asm.tree.ClassNode

private const val MIXIN_DESC = "Lorg/spongepowered/asm/mixin/Mixin;"

/**
 * Renaming classes
 * Last update on 2024/10/02
 */
object ClassRenameTransformer : Transformer("ClassRename", Category.Renaming) {

    private val dictionary by setting("Dictionary", "Alphabet")
    private val parent by setting("Parent", "net/spartanb312/obf/")
    private val prefix by setting("Prefix", "")
    private val reversed by setting("Reversed", false)
    private val shuffled by setting("Shuffled", false)
    private val corruptedName by setting("CorruptedName", false)
    private val corruptedNameExclusion by setting("CorruptedNameExclusion", listOf())
    private val exclusion by setting(
        "Exclusion", listOf(
            "net/spartanb312/Example",
            "net/spartanb312/component/Component**",
            "net/spartanb312/package/**"
        )
    )

    // Target thật của mọi @Mixin trong project (quét tự động từ annotation value/targets),
    // không cho CorruptedName chèn \u0000 vào các class này - vì Mixin framework resolve
    // target bằng tên class, nếu tên bị hỏng thì mixin apply sai/crash lúc runtime.
    private var autoMixinTargets: Set<String> = emptySet()

    private val ClassNode.malNamePrefix
        get() = if (corruptedName) {
            if (corruptedNameExclusion.any { ex -> name.startsWith(ex) } || name in autoMixinTargets) {
                Logger.debug("    MalName excluded for $name")
                ""
            } else "\u0000"
        } else ""

    /**
     * Quét mọi class nằm trong mixinPackages (ResourceCache.mixinClasses), đọc annotation
     * @Mixin của từng class, lấy ra target thật qua 2 thuộc tính:
     * - value: Class<?>[] -> target là class nằm trong chính project (reference bytecode-level)
     * - targets: String[] -> target viết bằng tên chuỗi (dùng cho private-access class),
     *   đây là trường hợp nguy hiểm nhất vì Mixin so khớp bằng TEXT, không qua remap bytecode.
     */
    private fun ResourceCache.collectMixinTargets(): Set<String> {
        val result = mutableSetOf<String>()
        mixinClasses.forEach { mixinClass ->
            val annotation = mixinClass.visibleAnnotations?.find { it.desc == MIXIN_DESC } ?: return@forEach
            val values = annotation.values ?: return@forEach
            var i = 0
            while (i < values.size - 1) {
                val key = values[i] as? String
                val value = values[i + 1]
                when (key) {
                    "value" -> (value as? List<*>)?.forEach { v ->
                        (v as? Type)?.let { result.add(it.internalName) }
                    }

                    "targets" -> (value as? List<*>)?.forEach { v ->
                        (v as? String)?.let { result.add(it.replace('.', '/')) }
                    }
                }
                i += 2
            }
        }
        return result
    }

    private lateinit var lastDict: NameGenerator
    private val suffix get() = if (reversed) "\u200E" else ""
    fun nextAppendClassName(classNode: ClassNode): String {
        return parent  + classNode.malNamePrefix + prefix + lastDict.nextName() + suffix
    }

    override fun ResourceCache.transform() {
        Logger.info(" - Renaming classes...")
        if (corruptedName) {
            autoMixinTargets = collectMixinTargets()
            if (autoMixinTargets.isNotEmpty())
                Logger.info("    Auto-excluded ${autoMixinTargets.size} mixin target classes from CorruptedName")
        }
        Logger.info("    Generating mappings for classes...")
        val equalsExclusion = exclusion.filter { !it.endsWith("**") }
        val startWithExclusion = buildList { exclusion.forEach { if (it.endsWith("**")) add(it.removeSuffix("**")) } }
        val nameGenerator = NameGenerator.getByName(dictionary)
        lastDict = nameGenerator
        val mappings = mutableMapOf<String, String>()
        val count = count {
            val classes = if (shuffled) nonExcluded.shuffled() else nonExcluded
            classes.forEach {
                if (it.name.notInList(equalsExclusion, false) && it.name.notInList(startWithExclusion)) {
                    mappings[it.name] = parent + it.malNamePrefix + prefix + nameGenerator.nextName() + suffix
                    add()
                }
            }
        }.get()

        Logger.info("    Applying mappings for classes...")
        applyRemap("classes", mappings, true)
        Logger.info("    Renamed $count classes")
    }

}