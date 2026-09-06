import org.gradle.api.DefaultTask
import org.gradle.api.file.DirectoryProperty
import org.gradle.api.file.FileSystemOperations
import org.gradle.api.tasks.InputDirectory
import org.gradle.api.tasks.OutputDirectory
import org.gradle.api.tasks.TaskAction
import javax.inject.Inject

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.plugin.compose")
    jacoco
}

val repositoryRoot = rootProject.projectDir.resolve("../..").canonicalFile
val kasseeWeb = repositoryRoot.resolve("apps/kassee-web")
val canonicalKasSeeSite = repositoryRoot.resolve("target/kassee-web/site")
val kasSeeWebUiAssets = layout.buildDirectory.dir("generated/kassee-web-ui")
val runtimeBuilder = repositoryRoot.resolve("tools/build/web/build_kassee_runtime.py")
val pythonCommand = providers.environmentVariable("PYTHON").orElse(
    if (System.getProperty("os.name").lowercase().contains("windows")) "python" else "python3",
)

val syncKasSignerRuntime by tasks.registering(Exec::class) {
    group = "build setup"
    description = "Builds the canonical KasSee Web/WASM runtime under repository target/."

    inputs.file(runtimeBuilder)
    inputs.file(repositoryRoot.resolve("qa/config/toolchains.env"))
    inputs.file(kasseeWeb.resolve("Cargo.toml"))
    inputs.file(kasseeWeb.resolve("Cargo.lock"))
    inputs.files(fileTree(kasseeWeb.resolve("src")) { include("**/*.rs") })
    inputs.files(fileTree(kasseeWeb.resolve("web")) { exclude("pkg/**") })
    for (crate in listOf("online-watcher", "shared-signer", "offline-signer")) {
        inputs.file(repositoryRoot.resolve("crates/$crate/Cargo.toml"))
        inputs.files(fileTree(repositoryRoot.resolve("crates/$crate/src")) { include("**/*.rs") })
    }
    outputs.dir(canonicalKasSeeSite)
    commandLine(pythonCommand.get(), runtimeBuilder.absolutePath, "--mode", "release")
}

val verifyKasSignerRuntime by tasks.registering {
    group = "verification"
    description = "Fails if the canonical KasSee Web runtime is incomplete."
    dependsOn(syncKasSignerRuntime)
    doLast {
        val required = listOf(
            canonicalKasSeeSite.resolve("index.html"),
            canonicalKasSeeSite.resolve("css/app.css"),
            canonicalKasSeeSite.resolve("js/main.js"),
            canonicalKasSeeSite.resolve("js/mobile/native_adaptations.js"),
            canonicalKasSeeSite.resolve("pkg/kassee_web.js"),
            canonicalKasSeeSite.resolve("pkg/kassee_web_bg.wasm"),
        )
        val missing = required.filterNot { it.isFile && it.length() > 0L }
        check(missing.isEmpty()) {
            "Canonical KasSee runtime is incomplete: ${missing.joinToString { it.relativeTo(repositoryRoot).path }}"
        }
    }
}

abstract class SyncKasSeeWebUiTask : DefaultTask() {
    @get:InputDirectory
    abstract val webSite: DirectoryProperty

    @get:OutputDirectory
    abstract val outputDirectory: DirectoryProperty

    @get:Inject
    abstract val fileSystemOperations: FileSystemOperations

    @TaskAction
    fun sync() {
        fileSystemOperations.sync {
            into(outputDirectory.get().asFile)
            from(webSite.get().asFile) { into("kassee") }
        }
    }
}

val syncKasSeeWebUi = tasks.register<SyncKasSeeWebUiTask>("syncKasSeeWebUi") {
    dependsOn(verifyKasSignerRuntime)
    group = "build setup"
    description = "Copies the canonical KasSee site into Gradle-owned generated Android assets."
    webSite.fileValue(canonicalKasSeeSite)
    outputDirectory.set(kasSeeWebUiAssets)
}

android {
    namespace = "org.kassigner.kassigner"
    compileSdk = 37

    defaultConfig {
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        applicationId = "org.kassigner.kassigner"
        minSdk = 26
        targetSdk = 37
        versionCode = 20000
        versionName = "2.0.0"
        vectorDrawables.useSupportLibrary = true
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    testOptions.unitTests.isIncludeAndroidResources = true
    buildTypes {
        debug { enableUnitTestCoverage = true }
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
    }
}

androidComponents {
    onVariants(selector().all()) { variant ->
        variant.sources.assets?.addGeneratedSourceDirectory(
            syncKasSeeWebUi,
            SyncKasSeeWebUiTask::outputDirectory,
        )
    }
}

tasks.named("preBuild") {
    dependsOn(syncKasSeeWebUi)
}

// Gradle 9.x may execute asset merging independently of preBuild ordering.
// Make the generated KasSee asset producer an explicit prerequisite so the
// mapped output directory is never queried before syncKasSeeWebUi completes.
tasks.matching { it.name.startsWith("merge") && it.name.endsWith("Assets") }.configureEach {
    dependsOn(syncKasSeeWebUi)
}

dependencies {
    val composeBom = platform("androidx.compose:compose-bom:2026.06.01")
    implementation(composeBom)

    implementation("androidx.activity:activity-compose:1.13.0")
    implementation("androidx.fragment:fragment-ktx:1.9.0")
    implementation("androidx.compose.foundation:foundation")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-extended")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.11.0")
    implementation("androidx.webkit:webkit:1.17.0")
    implementation("androidx.biometric:biometric:1.1.0")

    testImplementation("junit:junit:4.13.2")
    testImplementation("androidx.test:core-ktx:1.7.0")
    testImplementation("org.robolectric:robolectric:4.16.1")
    androidTestImplementation("androidx.test:core-ktx:1.7.0")
    androidTestImplementation("androidx.test:runner:1.7.0")
    androidTestImplementation("androidx.test:rules:1.7.0")
    androidTestImplementation("androidx.test.ext:junit-ktx:1.3.0")
    androidTestImplementation("androidx.test.espresso:espresso-core:3.7.0")
    debugImplementation("androidx.compose.ui:ui-tooling")
}
