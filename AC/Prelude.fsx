[<CLIMutable>]
type RequestAuthorizationToken =
    { ResponseType: string
      ClientId: string
      RedirectUrl: string }


type SignInRequest =
    { Username: string
      Password: string
      ClientId: string
      RedirectUrl: string }


type ExchangeTokenRequest =
    { GrantType: string
      ClientId: string
      ClientSecret: string
      AuthorizationCode: string
      RedirectUrl: string }


let ClientServer = "http://localhost:5000"
let AuthServer = "http://localhost:5001"
let ResourceServer = "http://localhost:5002"


let ClientId = "client"
let ClientSecret = "secret"
