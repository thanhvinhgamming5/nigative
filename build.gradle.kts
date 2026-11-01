import org.jetbrains.kotlin.gradle.utils.extendsFrom

plugins {
    java
    kotlin("jvm")
    id("com.github.johnrengelman.shadow") version "8.1.1"
}

repositories {
    mavenCentral()
    maven("https://repo1.maven.org/maven2/")
    maven("https://mvnrepository.com/artifact/")
}

val kotlinxCoroutineVersion = "1.7.3"
val asmVersion = "9.7"

val library: Configuration by configurations.creating

configurations {
    api.extendsFrom(named("library"))
}

dependencies {
    library(project(":genesis"))
    //Kotlin
    library(kotlin("stdlib"))
    library("org.jetbrains.kotlinx:kotlinx-coroutines-core:$kotlinxCoroutineVersion")

    //ASM
    library("org.ow2.asm:asm:$asmVersion")
    library("org.ow2.asm:asm-tree:$asmVersion")
    library("org.ow2.asm:asm-commons:$asmVersion")
    library("org.ow2.asm:asm-analysis:$asmVersion")

    //GSON
    library("com.google.code.gson:gson:2.10")

    //GUI
    library("com.miglayout:miglayout-swing:5.3")
    library("com.github.weisj:darklaf-core:3.0.2")

    library("org.apache.commons:commons-lang3:3.0")
    library("javassist:javassist:3.12.1.GA")

//    api(library)

}

tasks {

    compileJava {
        options.encoding = "UTF-8"
        sourceCompatibility = "1.8"
        targetCompatibility = "1.8"
    }

    compileKotlin {
        kotlinOptions {
            jvmTarget = "1.8"
        }
    }

    jar {
        enabled = false // shadowJar replaces this task (same output name)
    }

    shadowJar {
        // Bundle only the "library" configuration (same set as before)
        configurations = listOf(library)
        archiveBaseName.set(project.name.lowercase())
        archiveClassifier.set("")
        duplicatesStrategy = DuplicatesStrategy.EXCLUDE

        manifest {
            attributes(
                "Main-Class" to "net.spartanb312.grunt.GruntKt"
            )
        }

        // minimize disabled: Grunt uses reflection to load transformers
        // minimize { ... }

        exclude(
            "META-INF/versions/**",
            "module-info.class",
            "META-INF/*.SF", "META-INF/*.DSA", "META-INF/*.RSA",
            "META-INF/LICENSE*", "META-INF/NOTICE*", "META-INF/maven/**",
            "DebugProbesKt.bin", "**/*.kotlin_module", "**/*.kotlin_builtins"
        )
    }

    // `gradle build` also produces the slim fat-jar
    build {
        dependsOn(shadowJar)
    }

}