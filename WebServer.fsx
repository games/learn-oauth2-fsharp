#load "./runtime-scripts/Microsoft.AspNetCore.App-8.0.8.fsx"
#r "nuget: Oxpecker, 0.14.1"
#r "nuget: Serilog.AspNetCore"
#r "nuget: Microsoft.AspNetCore.Authentication.JwtBearer"


open System
open System.Security.Claims
open System.IdentityModel.Tokens.Jwt
open Microsoft.AspNetCore.Builder
open Microsoft.Extensions.DependencyInjection
open Microsoft.IdentityModel.Tokens
open Serilog
open Oxpecker


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


let run (port: uint) (endpoints: Endpoint seq) =
    Log.Logger <- LoggerConfiguration().WriteTo.Console().CreateLogger()

    let builder = WebApplication.CreateBuilder()
    builder.Services.AddSerilog().AddRouting().AddOxpecker() |> ignore

    let app = builder.Build()
    app.UseSerilogRequestLogging().UseRouting().UseOxpecker(endpoints) |> ignore
    app.Run($"http://localhost:{port}")
