# ScotAccount Client

This project implements a client application for the ScotAccount service, providing OAuth2/OIDC authentication with JWT-based client assertions. It consists of two main modules:

- `scotaccount-jwt`: A utility module for JWT operations and key management
- `scotaccountclient`: The main Spring Boot application implementing the OAuth2 client

## Features

- OAuth2/OIDC authentication with ScotAccount
- JWT-based client assertions for secure client authentication
- PKCE (Proof Key for Code Exchange) support
- Automatic JWKS (JSON Web Key Set) validation
- Session management and token handling
- Comprehensive logging and error handling

## Prerequisites

- Java 17 or higher
- Maven 3.6 or higher
- Access to ScotAccount service (client ID and integration environment access)
- RSA key pair for client assertions

## Project Structure

```
scotaccount-parent/
├── scotaccount-jwt/          # JWT utilities module
│   ├── src/main/java/uk/aiapplied/scotaccount/jwt/
│   │   └── JwtUtil.java      # Core JWT operations
│   └── src/main/resources/
│       └── keys/             # RSA key pair for JWT operations
│           ├── private.pem   # Your RSA private key
│           └── public.pem    # Your RSA public key
├── scotaccountclient/        # Main client application
│   ├── src/main/java/uk/aiapplied/scotaccountclient/
│   │   ├── SecurityConfig.java           # OAuth2/Security configuration
│   │   ├── CustomOAuth2AccessTokenResponseClient.java  # Token handling
│   │   └── LoggedInController.java       # Authentication success/failure handling
│   └── src/main/resources/
│       └── application.properties        # Application configuration
└── docs/                     # Additional documentation
```

## Setup Instructions

### 1. Key Generation and Setup

1. Generate an RSA key pair:

   ```bash
   # Generate private key
   openssl genpkey -algorithm RSA -out private.pem -pkeyopt rsa_keygen_bits:2048

   # Extract public key
   openssl rsa -pubout -in private.pem -out public.pem
   ```

2. Place the keys in `scotaccount-jwt/src/main/resources/keys/`
   - This location is required as the JwtUtil class uses these keys for client assertion generation
   - The private key is used to sign client assertions
   - The public key can be used for local testing/validation

### 2. Configuration

1. Update `application.properties`:

   ```properties
   # Your ScotAccount client ID
   spring.security.oauth2.client.registration.scotaccount.client-id=your_client_id

   # Other properties are pre-configured for the integration environment
   ```

### 3. Building and Running

1. Build the project:

   ```bash
   mvn clean install
   ```

2. Run the application:

   ```bash
   cd scotaccountclient
   mvn spring-boot:run
   ```

3. Access the application at `http://localhost:8080`

## Authentication Flow

1. **Client Assertion Generation**

   - When a token request is made, `JwtUtil` automatically generates a client assertion JWT
   - The JWT is signed with your private key
   - Claims include client ID, issuer, audience (token endpoint), and expiration

2. **Authorization Request**

   - User is redirected to ScotAccount's authorization endpoint
   - PKCE parameters are automatically generated and included
   - State parameter prevents CSRF attacks

3. **Token Exchange**

   - Authorization code is exchanged for tokens using client assertion
   - PKCE verifier is included in the token request
   - Tokens (access token, ID token) are validated using ScotAccount's JWKS

4. **Token Validation**
   - Public keys are fetched from ScotAccount's JWKS endpoint
   - Keys are cached to improve performance
   - Tokens are validated using the appropriate public key based on the `kid` header

## Key Components

### JwtUtil

- Handles JWT operations (creation, validation)
- Manages JWKS key retrieval and caching
- Generates client assertions for OAuth2 authentication
- Loads private key from `scotaccount-jwt/src/main/resources/keys/`

### SecurityConfig

- Configures OAuth2 client settings
- Sets up security filters and PKCE
- Manages authorization and token endpoints

### CustomOAuth2AccessTokenResponseClient

- Handles token exchange process
- Manages client assertion inclusion
- Processes token responses

### LoginController

- Handles authentication success/failure
- Manages user session
- Processes token claims

## Logging and Debugging

Logging is configured at TRACE level for detailed debugging:

```properties
logging.level.uk.aiapplied.scotaccountclient=TRACE
logging.level.org.springframework.security=TRACE
logging.level.org.springframework.web=TRACE
```

Check logs for:

- JWT generation and validation
- OAuth2 token requests and responses
- Authentication success/failure events

## Security Considerations

1. **Key Management**

   - Keep private key secure
   - Never commit keys to version control
   - Rotate keys periodically
   - Use appropriate key permissions

2. **Token Handling**

   - Tokens are validated using ScotAccount's JWKS
   - Session timeout is configured to 5 minutes
   - Secure cookie settings are enabled

3. **PKCE**
   - Automatically enabled for all authorization requests
   - Uses S256 method for code challenge
   - Verifier is securely stored in session

## Troubleshooting

1. **JWT Issues**

   - Verify key format (PKCS#8 for private, X.509 for public)
   - Check key permissions
   - Validate client assertion claims

2. **OAuth2 Errors**

   - Verify client ID configuration
   - Check PKCE parameters
   - Validate redirect URI configuration

3. **Token Validation**
   - Ensure JWKS endpoint is accessible
   - Check token format and claims
   - Verify key ID (kid) matching

## Support

For additional support:

1. Check detailed logs using TRACE level
2. Review error messages in browser console
3. Verify configuration against ScotAccount documentation
4. Contact ScotAccount support for integration issues

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
