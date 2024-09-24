#load "./WebServer.fsx"

open System.Text
open WebServer
open Microsoft.IdentityModel.Tokens

let key = Encoding.UTF8.GetBytes("1234567890123456")

let text = "Hello, world!"
let bytes = Encoding.UTF8.GetBytes(text)

let encrypted = encrypt key bytes
printfn "Encrypted: %A" encrypted

let decrypted = decrypt key encrypted
printfn "Decrypted: %A" decrypted


let code = "d4wF8w_RqjCBOpnhP5DbCpql-9LQYXl6_Rl9-KLMKu1c9T6iQg05feH2ak_PLcQcKRO_lVwKNg8ZtjU4UQsQsQ"
let origin = code |> Base64UrlEncoder.DecodeBytes |> decrypt key 
printfn "Origin: %A" origin
