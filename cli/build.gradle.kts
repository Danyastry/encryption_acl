plugins {
    id("encryption.java-conventions")
    application
}

dependencies {
    implementation(project(":core"))
    implementation(libs.picocli)
}

application {
    mainClass = "com.danyastry.encryption.cli.EncryptionCli"
    applicationName = "encryption"
}
