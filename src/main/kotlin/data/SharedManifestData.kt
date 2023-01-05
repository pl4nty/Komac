package data

import org.koin.core.annotation.Single
import org.koin.core.component.KoinComponent

@Single
class SharedManifestData : KoinComponent {
    lateinit var packageIdentifier: String
    lateinit var packageVersion: String
    var defaultLocale: String = ""
    var isNewPackage = false
    lateinit var latestVersion: String
}
