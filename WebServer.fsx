#load "./runtime-scripts/Microsoft.AspNetCore.App-8.0.8.fsx"
#r "nuget: Oxpecker, 0.14.1"
#r "nuget: Serilog.AspNetCore"
#r "nuget: Microsoft.AspNetCore.Authentication.JwtBearer"


open System
open System.Security.Claims
open System.IdentityModel.Tokens.Jwt
open System.Security.Cryptography
open Microsoft.AspNetCore.Builder
open Microsoft.Extensions.DependencyInjection
open Microsoft.IdentityModel.Tokens
open Serilog
open Oxpecker
open System.IO


type Errors = string


let jsonResult (result: Result<'T, Errors>) : EndpointHandler =
    fun ctx ->
        task {
            match result with
            | Ok data -> return! ctx.WriteJson {| value = data |}
            | Error error ->
                ctx.SetStatusCode 400
                return! ctx.WriteJson {| error = error |}
        }


let jwt key (expires: DateTime) (claims: (string * string) seq) =
    let token =
        JwtSecurityToken(
            claims = (claims |> Seq.map (fun (k, v) -> new Claim(k, v))),
            expires = Nullable expires,
            signingCredentials = SigningCredentials(key, SecurityAlgorithms.RsaSha256)
        )

    let handler = new JwtSecurityTokenHandler()
    handler.WriteToken(token)


let verifyJwt key (jwt: string) =
    try
        let handler = new JwtSecurityTokenHandler()

        let validation =
            TokenValidationParameters(
                IssuerSigningKey = key,
                ValidateIssuerSigningKey = true,
                ValidateIssuer = true,
                ValidIssuer = "AuthServer",
                ValidateAudience = false,
                ValidateLifetime = true
            )

        let result = handler.ValidateToken(jwt, validation)

        Ok result
    with ex ->
        Error ex


let encrypt (key: byte[]) (plainBytes: byte[]) =
    use aes = Aes.Create(Key = key)
    let ivBytes = aes.IV
    let encryptor = aes.CreateEncryptor(aes.Key, aes.IV)
    use ms = new MemoryStream()

    do
        use cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write)
        use writer = new BinaryWriter(cs)
        writer.Write(plainBytes)

    let dataBytes = ms.ToArray()
    let bytes = Array.zeroCreate<byte> (ivBytes.Length + dataBytes.Length)
    Array.Copy(ivBytes, 0, bytes, 0, ivBytes.Length)
    Array.Copy(dataBytes, 0, bytes, ivBytes.Length, dataBytes.Length)
    bytes


let decrypt (key: byte[]) (cipherBytes: byte[]) =
    let ivBytes = Array.zeroCreate<byte> 16
    let dataBytes = Array.zeroCreate<byte> (cipherBytes.Length - ivBytes.Length)
    Array.Copy(cipherBytes, 0, ivBytes, 0, ivBytes.Length)
    Array.Copy(cipherBytes, ivBytes.Length, dataBytes, 0, dataBytes.Length)

    use aes = Aes.Create(Key = key, IV = ivBytes)
    let decryptor = aes.CreateDecryptor(key, ivBytes)
    use ms = new MemoryStream(dataBytes)
    use cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read)
    use reader = new StreamReader(cs)
    let decrypted = reader.ReadToEnd()
    decrypted


let run (port: uint) (endpoints: Endpoint seq) =
    Log.Logger <- LoggerConfiguration().WriteTo.Console().CreateLogger()

    let builder = WebApplication.CreateBuilder()
    builder.Services.AddSerilog().AddRouting().AddOxpecker() |> ignore

    let app = builder.Build()
    app.UseSerilogRequestLogging().UseRouting().UseOxpecker(endpoints) |> ignore
    app.Run($"http://localhost:{port}")
