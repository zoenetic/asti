Class Test.WeakCrypto Extends %RegisteredObject
{

ClassMethod Run() As %Status
{
    set data = "payload"

    // crit:expect os.weak-crypto
    set h1 = $System.Encryption.MD5Hash(data)
    // crit:expect os.weak-crypto
    set h2 = $System.Encryption.SHA1Hash(data)

    // crit:expect-not os.weak-crypto
    set h3 = $System.Encryption.SHAHash(512, data)
    // crit:expect-not os.weak-crypto
    set h4 = $System.Encryption.SHAHash(256, data)
    quit $$$OK
}

}
