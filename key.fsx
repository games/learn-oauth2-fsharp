open System
open System.IO
open System.Security.Cryptography
open System.Security.Cryptography.X509Certificates

let makeCert () =
    let ecdsa = ECDsa.Create() // generate asymmetric key pair
    let req = new CertificateRequest("cn=oauth2", ecdsa, HashAlgorithmName.SHA256)
    let cert = req.CreateSelfSigned(DateTimeOffset.Now, DateTimeOffset.Now.AddYears(20))

    // Create PFX (PKCS #12) with private key
    File.WriteAllBytes("./keys/mycert.pfx", cert.Export(X509ContentType.Pfx))
    // Create Base 64 encoded CER (public key only)
    File.WriteAllText(
        "./keys/mycert.cer",
        "-----BEGIN CERTIFICATE-----\r\n"
        + Convert.ToBase64String(cert.Export(X509ContentType.Cert), Base64FormattingOptions.InsertLineBreaks)
        + "\r\n-----END CERTIFICATE-----"
    )

makeCert ()
