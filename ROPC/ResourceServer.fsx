#r @"nuget: FSharpPlus"
#load "../WebServer.fsx"
#load "./Prelude.fsx"

open Oxpecker
open WebServer
open Microsoft.IdentityModel.Tokens
open System.Security.Cryptography
open System.IO


let AuthServerCertificate =
    let rsa = RSA.Create()
    rsa.ImportFromPem(File.ReadAllText("../keys/public.pem"))
    RsaSecurityKey(rsa)


let requiresLoggedIn: EndpointMiddleware =
    fun next ctx ->
        let authorization = string ctx.Request.Headers.Authorization

        if authorization.StartsWith "Bearer " then
            let jwt = authorization[7..]
            let result = verifyJwt AuthServerCertificate jwt

            match result with
            | Ok(principal, token) -> text $"Great! You are logged in! " ctx
            | Error ex ->
                ctx.SetStatusCode 401
                ctx.WriteText ex.Message
        else


            let authorized, _ = ctx.Request.Cookies.TryGetValue "access_token"
            if authorized then next ctx else setStatusCode 401 ctx


let getUser: EndpointHandler = text "Great! You are logged in!"


run 5002u [ route "/user" (requiresLoggedIn getUser) ]
