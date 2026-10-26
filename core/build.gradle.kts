plugins {
    id("encryption.java-conventions")
    `java-library`
}

dependencies {
    implementation(libs.bouncycastle)
}
