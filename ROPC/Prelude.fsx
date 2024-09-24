type RequestAccessToken =
    { GrantType: string
      Username: string
      Password: string
      ClientId: string
      ClientSecret: string }


let AuthServer = "http://localhost:5001"
let ResourceServer = "http://localhost:5002"

let ClientId = "client"
let ClientSecret = "secret"
