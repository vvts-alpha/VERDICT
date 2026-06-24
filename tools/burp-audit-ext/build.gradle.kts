plugins {
    java
    // fat jar(Gson 同梱)を作る。Burp 拡張は単一 jar でロードするため。
    id("com.github.johnrengelman.shadow") version "8.1.1"
}

group = "com.amraam"
version = "0.1.0"

repositories { mavenCentral() }

dependencies {
    // Montoya API は Burp が実行時に供給する → compileOnly。2026.4 でコンパイル検証済み(古い Burp なら下げる)。
    compileOnly("net.portswigger.burp.extensions:montoya-api:2026.4")
    // JSON は jar に同梱(Burp は供給しない)。
    implementation("com.google.code.gson:gson:2.11.0")
}

java {
    toolchain { languageVersion.set(JavaLanguageVersion.of(17)) }
}

tasks.shadowJar {
    archiveBaseName.set("amraam-burp-audit")
    archiveClassifier.set("")
    archiveVersion.set("")
    // Gson の名前衝突を避けたい場合は relocate を有効化(任意):
    // relocate("com.google.gson", "com.amraam.shadow.gson")
}

tasks.named("build") { dependsOn("shadowJar") }
