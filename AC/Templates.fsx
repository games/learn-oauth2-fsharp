#r "nuget: Oxpecker, 0.14.1"
#load "./Prelude.fsx"

open Oxpecker
open Oxpecker.ViewEngine
open Prelude


let grantAccess (client: RequestAuthorizationToken) =
    html () {
        head () { title () { "Grant Access" } }

        body () {
            h1 () { "Sign In" }
            h3 () { $"[{client.ClientId}] is requesting access to your account" }

            form (action = "/signin", method = "post") {
                div () { input (type' = "text", name = "username", placeholder = "Username") }
                div () { input (type' = "password", name = "password", placeholder = "Password") }
                div () { input (type' = "hidden", name = "clientId", value = client.ClientId) }
                div () { input (type' = "hidden", name = "redirectUrl", value = client.RedirectUrl) }
                input (type' = "submit", value = "Sign In")
                div () { "user/password" }
            }
        }
    }
