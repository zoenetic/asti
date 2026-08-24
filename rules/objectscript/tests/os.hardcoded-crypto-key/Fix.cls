Class Test.HardcodedCryptoKey Extends %RegisteredObject
{

ClassMethod Run() As %Status
{
    set data = "payload"
    set iv = "0123456789abcdef"
    set mykey = $System.Encryption.GenCryptRand(16)

    // crit:expect os.hardcoded-crypto-key
    set enc = $System.Encryption.AESCBCEncrypt(data, "hardcodedkey1234", iv)
    // crit:expect os.hardcoded-crypto-key
    set dec = $System.Encryption.AESCBCDecrypt(data, "hardcodedkey1234", iv)

    // crit:expect-not os.hardcoded-crypto-key
    set enc2 = $System.Encryption.AESCBCEncrypt(data, mykey, iv)
    // crit:expect-not os.hardcoded-crypto-key
    set dec2 = $System.Encryption.AESCBCDecrypt(data, mykey, iv)
    quit $$$OK
}

}
