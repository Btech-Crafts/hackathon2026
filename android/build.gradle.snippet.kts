// Add to your app/build.gradle.kts dependencies block.
dependencies {
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.7.3")
    implementation("androidx.core:core-ktx:1.12.0")
    implementation("androidx.appcompat:appcompat:1.6.1")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.7.0")

    // CameraX (preview + analysis use-cases)
    implementation("androidx.camera:camera-core:1.3.1")
    implementation("androidx.camera:camera-camera2:1.3.1")
    implementation("androidx.camera:camera-lifecycle:1.3.1")
    implementation("androidx.camera:camera-view:1.3.1")

    // ML Kit Barcode Scanning (QR decode, camera + gallery)
    implementation("com.google.mlkit:barcode-scanning:17.2.0")

    // No Retrofit/OkHttp required — QR + payment evaluators use
    // HttpURLConnection + org.json to keep the APK lean.
}
