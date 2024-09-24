#r @"nuget: FSharpPlus"
#load "../WebServer.fsx"
#load "./Prelude.fsx"
#load "./Templates.fsx"

open Oxpecker
open Microsoft.IdentityModel.Tokens
open System.Text
open System.Security.Cryptography
open System.IO
open FSharpPlus
open Prelude
open WebServer
open System
open System.Collections.Generic


let aesKey = Encoding.UTF8.GetBytes("1234567890123456")

let AuthServerKey =
    let rsa = RSA.Create()
    rsa.ImportFromPem(File.ReadAllText("../keys/private.pem"))
    RsaSecurityKey(rsa)


let authorizationCodeCache = Dictionary<string, DateTimeOffset>()


let login: EndpointHandler =
    fun ctx ->
        task {
            let req = ctx.BindQuery<RequestAuthorizationToken>()

            if req.ClientId <> ClientId then
                return! ctx.WriteText "Invalid client credentials"
            else
                return! ctx.WriteHtmlView(Templates.grantAccess req)
        }


let signIn: EndpointHandler =

    let validateClientCredentials (args: SignInRequest) =
        if args.ClientId = ClientId then
            Ok args
        else
            Error "Invalid client credentials"

    let validateUserCredentials (args: SignInRequest) =
        if args.Username = "user" && args.Password = "password" then
            Ok args
        else
            Error "Invalid user credentials"

    let generateAuthorizationCode (args: SignInRequest) =
        [ args.ClientId; args.RedirectUrl ]
        |> String.concat "|"
        |> Encoding.UTF8.GetBytes
        |> encrypt aesKey
        |> Base64UrlEncoder.Encode


    let generateRedirectUrl (args: SignInRequest) =
        let code = generateAuthorizationCode args
        authorizationCodeCache.Add(code, DateTimeOffset.Now.AddMinutes(5.))
        Ok $"{args.RedirectUrl}?authorization_code={code}"


    fun ctx ->
        task {
            let args =
                (fun user password clientId redirectUrl ->
                    { Username = user
                      Password = password
                      ClientId = clientId
                      RedirectUrl = redirectUrl })
                <!> ctx.TryGetFormValue "username"
                <*> ctx.TryGetFormValue "password"
                <*> ctx.TryGetFormValue "clientId"
                <*> ctx.TryGetFormValue "redirectUrl"
                |> function
                    | Some args -> Ok args
                    | None -> Error "Invalid form data"

            let result =
                args
                >>= validateClientCredentials
                >>= validateUserCredentials
                >>= generateRedirectUrl

            match result with
            | Ok redirectUrl -> return! redirectTo redirectUrl true ctx
            | Error error -> return! ctx.WriteText error
        }


let exchangeForToken: EndpointHandler =

    let validateClientCredentials (args: ExchangeTokenRequest) =
        if args.ClientId = ClientId && args.ClientSecret = ClientSecret then
            Ok args
        else
            Error "Invalid client credentials"

    let validateAuthorizationCode (args: ExchangeTokenRequest) =
        match authorizationCodeCache.TryGetValue(args.AuthorizationCode) with
        | true, expiration when expiration >= DateTimeOffset.Now ->
            let ciphers = Base64UrlEncoder.DecodeBytes args.AuthorizationCode
            let plain = decrypt aesKey ciphers
            let parts = plain.Split("|", StringSplitOptions.RemoveEmptyEntries)

            if parts.Length <> 2 then
                Error "Parts should be 2"
            elif parts[0] <> args.ClientId then
                Error $"Invalid client id: {parts[0]} <> {args.ClientId}"
            elif parts[1] <> args.RedirectUrl then
                Error $"Invalid redirect url: {parts[1]} <> {args.RedirectUrl}"
            else
                authorizationCodeCache.Remove(args.AuthorizationCode) |> ignore
                Ok args
        | _ -> Error "Authorization code is not found or expired"

    let generateAccessToken (req: ExchangeTokenRequest) =
        let exp = DateTime.UtcNow.AddMinutes(30.0)
        let token = jwt AuthServerKey exp [ "iss", "AuthServer" ]
        Ok token

    fun ctx ->
        task {
            let! req = ctx.BindJson<ExchangeTokenRequest>()

            let result =
                validateClientCredentials req
                >>= validateAuthorizationCode
                >>= generateAccessToken

            match result with
            | Ok token -> return! ctx.WriteJson {| value = token |}
            | Error error ->
                ctx.SetStatusCode 400
                return! ctx.WriteText error
        }


run
    5001u
    [ GET [ route "/login" login ]
      POST [ route "/signin" signIn; route "/exchange_token" exchangeForToken ] ]
