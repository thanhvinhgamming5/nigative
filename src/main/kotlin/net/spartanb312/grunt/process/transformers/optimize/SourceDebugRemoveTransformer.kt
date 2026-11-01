package net.spartanb312.grunt.process.transformers.optimize

import net.spartanb312.grunt.config.setting
import net.spartanb312.grunt.process.Transformer
import net.spartanb312.grunt.process.resource.NameGenerator
import net.spartanb312.grunt.process.resource.ResourceCache
import net.spartanb312.grunt.utils.count
import net.spartanb312.grunt.utils.logging.Logger
import net.spartanb312.grunt.utils.notInList
import org.objectweb.asm.tree.LineNumberNode
import kotlin.random.Random

/**
 * Remove or replace source debug info in class
 * Last update on 2024/06/26
 */
object SourceDebugRemoveTransformer : Transformer("SourceDebugRemove", Category.Optimization) {

    private val sourceDebug by setting("SourceDebug", true)
    private val lineDebug by setting("LineDebug", true)
    private val renameSourceDebug by setting("RenameSourceDebug", false)

    // Same "Dictionary" convention as ClassRename/MethodRename/StringClassEncrypt etc:
    // "Alphabet", "Numbers", "ConfuseIL", "Confuse0O", "ConfuseS5", "Arabic" or "Custom"
    // (reads Settings.CustomDictionaryFile, one identifier per line). Replaces the old
    // fixed SourceNames list - the generated base name gets a random extension appended.
    private val dictionary by setting("Dictionary", "Alphabet")
    private val extensions by setting("Extensions", listOf("java", "kt"))
    private val exclusion by setting("Exclusion", listOf())

    override fun ResourceCache.transform() {
        Logger.info(" - Removing/Editing debug information...")
        val nameGenerator = NameGenerator.getByName(dictionary)
        val count = count {
            nonExcluded.asSequence()
                .filter { it.name.notInList(exclusion) }
                .forEach { classNode ->
                    if (sourceDebug) {
                        if (renameSourceDebug) {
                            val ext = extensions.random(Random)
                            classNode.sourceDebug = "${nameGenerator.nextName()}.$ext"
                            classNode.sourceFile = "${nameGenerator.nextName()}.$ext"
                        } else {
                            classNode.sourceDebug = null
                            classNode.sourceFile = null
                        }
                        add()
                    }
                    if (lineDebug) classNode.methods.forEach { methodNode ->
                        methodNode.instructions.toList().forEach { insn ->
                            if (insn is LineNumberNode) {
                                methodNode.instructions.remove(insn)
                                add()
                            }
                        }
                    }
                }
        }.get()
        Logger.info("    Removed/Edited $count debug information")
    }

}