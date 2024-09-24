#r @"nuget: FSharpPlus"
#load "../WebServer.fsx"
#load "./Prelude.fsx"

open System
open FSharpPlus
open Oxpecker
open WebServer
open Prelude
open Microsoft.IdentityModel.Tokens
open System.Security.Cryptography
open System.IO


let AuthServerKey =
    let rsa = RSA.Create()
    rsa.ImportFromPem(File.ReadAllText("../keys/private.pem"))
    RsaSecurityKey(rsa)


let auth: EndpointHandler =

    let validateClientCredentials (req: RequestAccessToken) =
        if req.ClientId = ClientId && req.ClientSecret = ClientSecret then
            Ok req
        else
            Error "Invalid client credentials"

    let validateUserCredentials (req: RequestAccessToken) =
        if req.Username = "user" && req.Password = "password" then
            Ok req
        else
            Error "Invalid user credentials"

    let generateAccessToken (req: RequestAccessToken) =
        let exp = DateTime.UtcNow.AddMinutes(30.0)
        let token = jwt AuthServerKey exp [ "iss", "AuthServer" ]
        Ok token

    fun ctx ->
        task {
            let! req = ctx.BindJson<RequestAccessToken>()

            let result =
                validateClientCredentials req
                >>= validateUserCredentials
                >>= generateAccessToken

            return! jsonResult result ctx
        }


run 5001u [ POST [ route "/auth" auth ] ]
