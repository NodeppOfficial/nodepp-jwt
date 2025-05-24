# NodePP JWT: Simple JSON Web Token Implementation

This project offers a straightforward and lightweight implementation of JSON Web Tokens (JWTs) within the NodePP environment. JWTs are a compact and self-contained way for securely transmitting information between parties as a JSON object. This library allows you to easily generate, sign, and verify JWTs in your asynchronous, event-driven NodePP applications for authentication and authorization purposes.

## Key Features

- **JWT Encoding (Signing):** Enables the creation and signing of JWTs with a specified algorithm.
- **JWT Decoding (Verification):** Provides functionality to verify the signature of a JWT and decode its claims.
- **Algorithm Support:** Likely supports common JWT signing algorithms such as HMAC.
- **Simple API:** Offers an easy-to-use API for generating and verifying tokens within NodePP.
- **Lightweight:** Minimal dependencies, focusing on core JWT functionality.
- **Asynchronous Operations:** Designed to work seamlessly within NodePP's asynchronous event loop.

## Example
```cpp
#define SECRET "HELLOWORLDPASS"

#include <nodepp/nodepp.h>
#include <nodepp/json.h>
#include <jwt/jwt.h>

using namespace nodepp;

void onMain() {

    object_t obj ({
        { "user", "EDBC_REPO" },
        { "pass", "123456789" },
        { "payl", "Hello World" }
    });

    auto token = jwt::HS256::encode( json::stringify(obj), SECRET );
    if( jwt::HS256::verify( token, SECRET ) ) { 
        conio::done( "valid token: " ); console::log( token );
        console::log( "payload", jwt::HS256::decode( token ) );
    } else {
        conio::error( "invalid token: " );
        console::log( token );
    }

}
```

## Algorithms
```bash
📌: HS256
📌: HS341
📌: HS512
```

## Compilation
```bash
💻: g++ -o main main.cpp -I ./include ; ./main
```
