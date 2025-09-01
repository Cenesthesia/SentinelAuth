plugins {
    `java-library`
    jacoco
}

group = "com.cenesthesia"
version = "0.0.1"

java {
    sourceCompatibility = JavaVersion.VERSION_11
    targetCompatibility = JavaVersion.VERSION_11

    withJavadocJar()
    withSourcesJar()
}

base {
    archivesName = "sentinelauth-core"
}

repositories {
    mavenCentral()
}

dependencies {
    // Логирование
    implementation("org.slf4j:slf4j-api:2.0.9")

    // Тестирование
    testImplementation(platform("org.junit:junit-bom:5.10.0"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testImplementation("org.junit.jupiter:junit-jupiter-params")
}

tasks.withType<JavaCompile> {
    options.encoding = "UTF-8"
    options.compilerArgs.addAll(listOf("-Xlint:all", "-Xlint:-processing"))
}

tasks.withType<Javadoc> {
    options.encoding = "UTF-8"
    (options as StandardJavadocDocletOptions).addBooleanOption("Xdoclint:all,-missing", true)
}

tasks.test {
    useJUnitPlatform {
        includeTags("unit")
    }

    systemProperties = mapOf(
        "junit.jupiter.execution.parallel.enabled" to "true",
        "junit.jupiter.execution.parallel.mode.default" to "concurrent"
    )

    maxParallelForks = Runtime.getRuntime().availableProcessors() / 2
    failFast = false

    testLogging {
        events("passed", "skipped", "failed")
        showStandardStreams = true
    }

    reports {
        html.required.set(true)
        junitXml.required.set(true)
    }

    finalizedBy(tasks.jacocoTestReport)
}

jacoco {
    toolVersion = "0.8.10"
}

tasks.jacocoTestReport {
    dependsOn(tasks.test)

    reports {
        xml.required.set(true)
        html.required.set(true)
    }

    classDirectories.setFrom(
        files(classDirectories.files.map {
            fileTree(it).exclude(
                "**/internal/**",
                "**/config/**"
            )
        })
    )
}

tasks.register<JacocoCoverageVerification>("JacocoCoverageVerification") {
    violationRules {
        rule {
            limit {
                minimum = 0.8.toBigDecimal()
            }
        }

        rule {
            element = "CLASS"
            includes = listOf("com.cenesthesia.auth.*")
            limit {
                minimum = 0.9.toBigDecimal()
            }
        }
    }
}

tasks.register<Jar>("fatJar") {
    archiveClassifier.set("all")
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
    from(configurations.runtimeClasspath.get().map { zipTree(it) })
}

tasks.register("verifyAll") {
    dependsOn(
        tasks.test,
        tasks.jacocoTestCoverageVerification
    )
}

tasks.named("check") {
    dependsOn(tasks["verifyAll"])
}