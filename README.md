# ScotAccount Client

This Spring Boot application implements a client for the ScotAccount service, providing OAuth2/OIDC authentication with JWT-based client assertions.

## Features

- OAuth2/OIDC authentication with ScotAccount
- JWT-based client assertions for secure client authentication
- PKCE (Proof Key for Code Exchange) support
- Automatic JWKS (JSON Web Key Set) validation
- Session management and token handling
- User attribute fetching
- Comprehensive logging and error handling

## Prerequisites

- Java 21 or higher
- Maven 3.6 or higher
- Access to ScotAccount service (client ID and integration environment access)
- RSA key pair for client assertions

## Project Structure

```
scotaccountclient/
├── src/main/java/uk/aiapplied/scotaccountclient/
│   ├── ScotaccountClientApplication.java  # Main application class
│   ├── SecurityConfig.java                # OAuth2/Security configuration
│   ├── CustomOAuth2AccessTokenResponseClient.java  # Token handling
│   ├── LoginController.java              # Authentication handling
│   ├── LogoutController.java             # Logout handling
│   ├── HomeController.java               # Main application views
│   ├── AttributeService.java             # User attribute fetching
│   ├── JwtConfig.java                    # JWT configuration
│   ├── JwtUtil.java                      # JWT operations
│   ├── WebConfig.java                    # Web configuration
│   └── ServletInitializer.java           # Servlet initialization
└── src/main/resources/
    ├── application.properties            # Application configuration
    ├── templates/                        # Thymeleaf templates
    │   └── home.html                     # Main application view
    └── keys/                            # RSA key pair
        ├── private.pem                   # Private key for signing
        └── public.pem                    # Public key for verification
```

## Component Overview

### Core Components

#### ScotaccountClientApplication
- Main Spring Boot application class
- Initializes the application context
- Configures component scanning

#### SecurityConfig
- Configures OAuth2 client settings
- Sets up security filters and PKCE
- Manages authorization and token endpoints
- Configures session management
- Handles logout configuration

#### CustomOAuth2AccessTokenResponseClient
- Handles OAuth2 token exchange process
- Manages client assertion inclusion
- Processes and validates token responses
- Implements detailed request/response logging

### Controllers

#### LoginController
- Handles authentication success/failure
- Processes OAuth2/OIDC tokens
- Manages user session state
- Implements error handling and logging

#### LogoutController
- Manages user logout process
- Integrates with ScotAccount logout endpoint
- Handles post-logout redirects

#### HomeController
- Renders main application view
- Fetches and displays user attributes
- Manages authentication state display

### Services and Utilities

#### AttributeService
- Fetches user attributes from ScotAccount
- Processes JWT claims tokens
- Handles attribute response parsing
- Implements error handling

#### JwtUtil
- Manages JWT operations
- Generates client assertions
- Handles key loading and caching
- Implements JWT validation

#### JwtConfig
- Configures JWT components
- Manages public/private key loading
- Sets up JWT decoder

#### WebConfig
- Configures web-related beans
- Sets up RestTemplate for HTTP calls

## Authentication Flow

```plantuml
@startuml
actor User
participant "Client App" as Client
participant "ScotAccount" as Auth
database "User Attributes" as Attrs

User -> Client: Access protected resource
Client -> Auth: 1. Authorization request with PKCE
Auth -> User: 2. Login prompt
User -> Auth: 3. Provide credentials
Auth -> Client: 4. Authorization code
Client -> Auth: 5. Token request with client assertion
note right: Includes PKCE verifier
Auth -> Client: 6. Access & ID tokens
Client -> Attrs: 7. Fetch user attributes
Attrs -> Client: 8. User claims
Client -> User: 9. Display protected resource
@enduml
```

## Token Exchange Flow

```plantuml
@startuml
participant "CustomOAuth2AccessTokenResponseClient" as Client
participant "JwtUtil" as JWT
participant "ScotAccount Token Endpoint" as Token

Client -> JWT: 1. Generate client assertion
JWT -> JWT: 2. Load private key
JWT -> Client: 3. Signed JWT
Client -> Client: 4. Build token request
note right: Includes authorization code,\nPKCE verifier, client assertion
Client -> Token: 5. POST token request
Token -> Client: 6. Token response
Client -> Client: 7. Process tokens
note right: Validate and extract claims
Client -> Client: 8. Build OAuth2AccessTokenResponse
@enduml
```

## Attribute Fetching Flow

```plantuml
@startuml
participant "HomeController" as Home
participant "AttributeService" as Attr
participant "JwtUtil" as JWT
participant "ScotAccount Attributes API" as API

Home -> Attr: 1. Request attributes
Attr -> JWT: 2. Generate client assertion
JWT -> Attr: 3. Signed JWT
Attr -> API: 4. GET request with tokens
note right: Includes access token\nand client assertion
API -> Attr: 5. Claims token
Attr -> Attr: 6. Decode JWT claims
Attr -> Home: 7. Processed attributes
Home -> Home: 8. Update view model
@enduml
```

## Setup Instructions

### 1. Key Setup

1. Place your RSA keys in `src/main/resources/keys/`:
   - `private.pem`: For signing client assertions
   - `public.pem`: For token validation

### 2. Configuration

Update `application.properties`:

```properties
# ScotAccount Configuration
spring.security.oauth2.client.registration.scotaccount.client-id=your_client_id
spring.security.oauth2.client.registration.scotaccount.scope=openid gpg-45-medium scotaccount.gpg45.medium scotaccount.address scotaccount.email

# Attributes Endpoint
scotaccount.attributes.endpoint=https://api.integration.scotaccount.service.gov.scot/attributes

# Session Configuration
server.servlet.session.timeout=5m
```

### 3. Building and Running

```bash
# Build the project
mvn clean install

# Run the application
mvn spring-boot:run
```

Access the application at `http://localhost:8080`

## Security Considerations

1. **Key Management**
   - Secure key storage
   - Regular key rotation
   - Proper file permissions

2. **Token Security**
   - JWT validation
   - Session management
   - Secure cookie handling

3. **Error Handling**
   - Sanitized error messages
   - Comprehensive logging
   - Secure failure handling

## Logging

Configure logging in `application.properties`:

```properties
logging.level.uk.aiapplied.scotaccountclient=DEBUG
logging.level.org.springframework.security=DEBUG
logging.level.org.springframework.web=INFO
```

## Troubleshooting

1. **Authentication Issues**
   - Verify client configuration
   - Check key permissions
   - Review token validation

2. **Attribute Fetching Issues**
   - Validate access tokens
   - Check endpoint configuration
   - Review client assertions

3. **Session Issues**
   - Check timeout settings
   - Verify cookie configuration
   - Review security headers

## Support

For additional support or questions, please refer to the documentation in the `docs/` directory or contact the development team.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Submit a pull request with:
   - Clear description of changes
   - Updated documentation
   - Additional tests if needed

## Documentation

Detailed documentation is available in the following locations:

- API Documentation: `docs/javadoc/apidocs/index.html`
- Configuration Guide: `docs/configuration.md`
- Security Documentation: `docs/security.md`

## Security Notes

- Keep your private key secure and never commit it to version control
- Client assertion JWTs are generated on-demand and are valid for 6 months
- Rotate your keys regularly according to security best practices

## Troubleshooting

If you encounter issues:

1. Verify that your key files are in the correct location
2. Check that the keys are in the correct format (PEM)
3. Review the logs in `target/` directory for detailed error messages
4. Check the application logs for JWT generation and validation errors

## Support

For additional support or questions, please refer to the documentation in the `docs/` directory or contact the development team.

## Key Usage and Token Assertions

### RSA Key Pair Usage

1. **Private Key (`private.pem`)**
   - Used to sign client assertion JWTs
   - Never transmitted over the network
   - Required format: PKCS#8 PEM format
   - Example header: `-----BEGIN PRIVATE KEY-----`

2. **Public Key (`public.pem`)**
   - Used by ScotAccount to verify client assertions
   - Must be registered with ScotAccount service
   - Required format: X.509 PEM format
   - Example header: `-----BEGIN PUBLIC KEY-----`

### Client Assertion Generation

```plantuml
@startuml
participant "CustomOAuth2AccessTokenResponseClient" as Client
participant "JwtUtil" as JWT
database "Keys" as Keys

Client -> JWT: Request client assertion
JWT -> Keys: Load private key
JWT -> JWT: Build JWT claims
note right
  - iss: Client ID
  - sub: Client ID
  - aud: Token endpoint
  - exp: Now + 5 minutes
  - jti: Unique ID
end note
JWT -> JWT: Sign JWT with private key
JWT -> Client: Return signed assertion
@enduml
```

### Token Assertions and Validation

1. **Client Assertion Claims**
   ```json
   {
     "iss": "your_client_id",
     "sub": "your_client_id",
     "aud": "https://api.integration.scotaccount.service.gov.scot/token",
     "exp": 1234567890,
     "jti": "unique-identifier"
   }
   ```

2. **Assertion Validation**
   - Issuer (`iss`) must match client ID
   - Subject (`sub`) must match client ID
   - Audience (`aud`) must match token endpoint
   - Expiration (`exp`) must be in the future
   - JWT ID (`jti`) must be unique

3. **Signature Verification**
   - ScotAccount verifies signature using registered public key
   - Ensures assertion was created by legitimate client
   - Prevents token forgery and tampering

4. **Token Lifecycle**
   - Client assertions are generated for each token request
   - Assertions expire after 5 minutes
   - Each assertion has a unique JTI to prevent replay attacks

### Security Best Practices

1. **Key Protection**
   ```properties
   # File permissions (Unix)
   chmod 600 private.pem  # Read/write for owner only
   chmod 644 public.pem   # Read for all, write for owner
   ```

2. **Key Rotation Schedule**
   - Rotate keys every 6 months
   - Update public key with ScotAccount before expiry
   - Maintain key version history for audit

3. **Assertion Security**
   - Short expiration time (5 minutes)
   - Unique JTI per assertion
   - Strict audience validation
   - Claims minimization
