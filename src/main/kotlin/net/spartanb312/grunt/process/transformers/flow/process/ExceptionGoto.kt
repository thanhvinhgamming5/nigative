package net.spartanb312.grunt.process.transformers.flow.process

import net.spartanb312.genesis.kotlin.extensions.insn.*
import net.spartanb312.genesis.kotlin.extensions.LABEL
import net.spartanb312.genesis.kotlin.extensions.node
import net.spartanb312.genesis.kotlin.instructions
import org.objectweb.asm.Label
import org.objectweb.asm.tree.InsnList
import org.objectweb.asm.tree.LabelNode
import org.objectweb.asm.tree.MethodNode
import org.objectweb.asm.tree.TryCatchBlockNode

/**
 * Ported (re-implemented on ASM InsnList, not copied) from the idea behind
 * Skidfuscator's BasicRangeTransformer: instead of a plain GOTO, jump into a
 * block that is guaranteed to throw a fresh exception, with the real target
 * registered only as the handler of a try-catch range wrapped around that
 * throw. Decompilers have to reconstruct the exception table to even see
 * that this is just an unconditional jump.
 *
 * Original flow:            Obfuscated flow:
 *   A -> GOTO -> B             A -> GOTO -> [throw X] --try/catch--> [pop; GOTO B]
 */
object ExceptionGoto {

    // Side-effect free to build: callers never catch these elsewhere nearby,
    // so a mismatched catch block can't accidentally swallow it first.
    private val exceptionTypes = listOf(
        "java/lang/IllegalStateException",
        "java/lang/IllegalArgumentException",
        "java/lang/ArithmeticException",
        "java/lang/NegativeArraySizeException",
        "java/lang/ClassCastException",
        "java/lang/UnsupportedOperationException"
    )

    fun generate(
        targetLabel: LabelNode,
        methodNode: MethodNode
    ): InsnList {
        val exceptionType = exceptionTypes.random()
        val throwStart = Label()
        val throwEnd = Label()
        val handlerLabel = Label()

        val insnList = instructions {
            LABEL(throwStart)
            NEW(exceptionType)
            DUP
            INVOKESPECIAL(exceptionType, "<init>", "()V")
            ATHROW
            // Dead in the normal fall-through sense (ATHROW never falls through),
            // but reachable as the exception handler for the range right above it.
            LABEL(throwEnd)
            LABEL(handlerLabel)
            POP
            GOTO(targetLabel)
        }

        methodNode.tryCatchBlocks.add(
            TryCatchBlockNode(throwStart.node, throwEnd.node, handlerLabel.node, exceptionType)
        )

        return insnList
    }

}
