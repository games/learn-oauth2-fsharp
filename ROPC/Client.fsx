#r "nuget: FsHttp"
#load "../WebServer.fsx"
#load "./Prelude.fsx"

open Oxpecker
open System.Net
open System.Text.Json
open WebServer
open Prelude



module Templates =
    open Oxpecker.ViewEngine

    let loginPage =
        html () {
            head () { title () { "Login" } }

            body () {
                h1 () { "Login" }

                form (action = "/request_token", method = "post") {
                    div () { input (type' = "text", name = "username", placeholder = "Username") }
                    div () { input (type' = "password", name = "password", placeholder = "Password") }
                    input (type' = "submit", value = "Login")
                }
            }
        }


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
                return! redirectTo "/login" false ctx
        }


let loginPage = htmlView Templates.loginPage


let requestToken: EndpointHandler =
    fun ctx ->
        task {
            let username = ctx.TryGetFormValue "username"
            let password = ctx.TryGetFormValue "password"

            match username, password with
            | Some username, Some password ->
                let! rsp =
                    http {
                        POST $"{AuthServer}/auth"
                        body

                        jsonSerialize
                            { GrantType = "password"
                              Username = username
                              Password = password
                              ClientId = ClientId
                              ClientSecret = ClientSecret }
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
            | _ -> return! ctx.WriteText "Invalid credentials"
        }


run
    5000u
    [ route "/" index
      route "/login" loginPage
      route "/request_token" requestToken ]
