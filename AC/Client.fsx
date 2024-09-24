#r "nuget: FsHttp"
#load "../WebServer.fsx"
#load "./Prelude.fsx"

open Oxpecker
open System.Net
open System.Text.Json
open WebServer
open Prelude


open FsHttp


let index: EndpointHandler =
    fun ctx ->
        task {
            let authorized, accessToken = ctx.Request.Cookies.TryGetValue "access_token"

            if authorized then
                let! rsp =
                    http {
                        GET $"{ResourceServer}/user"
                        AuthorizationBearer accessToken
                    }
                    |> Request.sendTAsync

                let! body = rsp.content.ReadAsStringAsync()

                if rsp.statusCode <> HttpStatusCode.OK then
                    return!
                        [ $"HTTP Status Code: {rsp.statusCode}"
                          "The resource server returns an error"
                          body ]
                        |> String.concat "\n"
                        |> ctx.WriteText
                else
                    return! text body ctx
            else
                let callbackUrl = WebUtility.UrlEncode $"{ClientServer}/callback"

                let authUrl =
                    $"{AuthServer}/login?ClientId={ClientId}&RedirectUrl={callbackUrl}&ResponseType=code"

                return! redirectTo authUrl false ctx
        }


let callback: EndpointHandler =
    fun ctx ->
        task {
            let authorized, authorizationCode =
                ctx.Request.Query.TryGetValue "authorization_code"

            if not authorized then
                ctx.SetStatusCode 400
                return! ctx.WriteText "Invalid authorization code"

            let! rsp =
                http {
                    POST $"{AuthServer}/exchange_token"

                    body

                    jsonSerialize
                        { GrantType = "authorization_code"
                          ClientId = ClientId
                          ClientSecret = ClientSecret
                          AuthorizationCode = string authorizationCode
                          RedirectUrl = $"{ClientServer}/callback" }
                }
                |> Request.sendTAsync

            let! body = rsp.content.ReadAsStringAsync()

            if rsp.statusCode <> HttpStatusCode.OK then
                return!
                    [ $"HTTP Status Code: {rsp.statusCode}"
                      "The authorization server returns an error"
                      body ]
                    |> String.concat "\n"
                    |> ctx.WriteText
            else
                let result = JsonSerializer.Deserialize<{| value: string |}>(body)
                ctx.Response.Cookies.Append("access_token", result.value)
                return! redirectTo "/" true ctx
        }


run 5000u [ route "/" index; route "/callback" callback ]
