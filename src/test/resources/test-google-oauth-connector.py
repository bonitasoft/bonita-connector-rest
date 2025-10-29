#!/usr/bin/env python3
"""
Google OAuth2 Connector Test Script

This script helps test the Bonita OAuth2 connector with real Google credentials.
It handles the OAuth2 authorization flow and then calls the connector to exchange
the authorization code for an access token.

The key difference from the original script is that instead of making the HTTP
request directly, this script invokes the Bonita OAuth2 connector to perform
the token exchange.
"""

import json
import urllib.parse
import urllib.request
import webbrowser
import subprocess
import sys
import os
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

# Configuration - Fill these from your Google Cloud Console
CLIENT_ID = "***.apps.googleusercontent.com"
CLIENT_SECRET = "***"

# OAuth2 endpoints
AUTH_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"
SCOPE = "https://mail.google.com/"
REDIRECT_URI = "http://localhost:8080"

class CallbackHandler(BaseHTTPRequestHandler):
    """HTTP handler to capture OAuth2 callback"""

    def do_GET(self):
        """Handle the OAuth2 callback"""
        query = urlparse(self.path).query
        params = parse_qs(query)

        if 'code' in params:
            self.server.auth_code = params['code'][0]
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(b"""
                <html>
                <body>
                    <h1>Authorization Successful!</h1>
                    <p>The authorization code has been captured.</p>
                    <p>Now testing the Bonita OAuth2 connector...</p>
                    <p>You can close this window and return to the terminal.</p>
                </body>
                </html>
            """)
        else:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b"No authorization code received")

    def log_message(self, format, *args):
        """Suppress log messages"""
        pass

def get_authorization_code():
    """Start local server and get authorization code"""
    print("\n=== Step 1: Get Authorization Code ===")

    # Build authorization URL
    params = {
        'client_id': CLIENT_ID,
        'redirect_uri': REDIRECT_URI,
        'scope': SCOPE,
        'response_type': 'code',
        'access_type': 'offline',
        'prompt': 'consent'  # Force to show consent screen
    }

    auth_url = f"{AUTH_ENDPOINT}?{urllib.parse.urlencode(params)}"

    print(f"\nOpening browser to authorize...")
    print(f"\nIf the browser doesn't open, visit this URL:")
    print(f"{auth_url}\n")

    # Open browser
    webbrowser.open(auth_url)

    # Start local server to receive callback
    server = HTTPServer(('localhost', 8080), CallbackHandler)
    server.auth_code = None

    print("Waiting for authorization...")
    while server.auth_code is None:
        server.handle_request()

    return server.auth_code

def call_bonita_connector(auth_code):
    """Call the Bonita OAuth2 connector to exchange the code for a token"""
    print("\n=== Step 2: Exchange Code for Token Using Bonita Connector ===\n")

    # Find the project root (where pom.xml is located)
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.abspath(os.path.join(script_dir, '..', '..', '..'))

    print(f"Project root: {project_root}")
    print(f"Calling Bonita OAuth2 connector...\n")

    # Build the Maven command to run the connector
    mvn_cmd = [
        './mvnw',
        'exec:java',
        f'-Dexec.mainClass=org.bonitasoft.connectors.rest.Oauth2ConnectorRunner',
        '-Dexec.classpathScope=test',
        f'-Dexec.args={TOKEN_ENDPOINT} {CLIENT_ID} {CLIENT_SECRET} {auth_code} {REDIRECT_URI}'
    ]

    print("Running command:")
    print(" ".join(mvn_cmd))
    print("\n" + "=" * 80 + "\n")

    try:
        # Run the Maven command
        result = subprocess.run(
            mvn_cmd,
            cwd=project_root,
            capture_output=True,
            text=True,
            timeout=60
        )

        # Display the output
        if result.stdout:
            print(result.stdout)

        if result.stderr:
            # Maven outputs to stderr even for success, so check return code
            if result.returncode != 0:
                print("STDERR:", file=sys.stderr)
                print(result.stderr, file=sys.stderr)

        print("\n" + "=" * 80 + "\n")

        if result.returncode == 0:
            print("✓ Connector executed successfully!")
            return True
        else:
            print(f"✗ Connector failed with exit code {result.returncode}")
            return False

    except subprocess.TimeoutExpired:
        print("✗ Error: Command timed out after 60 seconds")
        return False
    except FileNotFoundError:
        print("✗ Error: ./mvnw not found. Make sure you're running this script from the project root.")
        print(f"   Looking for ./mvnw in: {project_root}")
        return False
    except Exception as e:
        print(f"✗ Error running connector: {e}")
        return False

def main():
    """Main function"""
    print("=" * 80)
    print("Google OAuth2 Connector Test for Bonita")
    print("=" * 80)

    # Check configuration
    if CLIENT_ID == "YOUR_CLIENT_ID.apps.googleusercontent.com":
        print("\n⚠️  ERROR: Please edit this script and set your CLIENT_ID and CLIENT_SECRET")
        print("\nGet them from: https://console.cloud.google.com/apis/credentials")
        print("\n1. Create OAuth 2.0 Client ID (Web application type)")
        print("2. Add http://localhost:8080 to Authorized redirect URIs")
        print("3. Copy Client ID and Client Secret to this script")
        print("4. Enable the APIs you want to test (e.g., Gmail API)")
        return

    # Get authorization code
    try:
        auth_code = get_authorization_code()
        print(f"✓ Authorization code received: {auth_code[:20]}...{auth_code[-10:]}")
    except KeyboardInterrupt:
        print("\n\nAborted by user")
        return
    except Exception as e:
        print(f"\n✗ Error getting authorization code: {e}")
        return

    # Call the Bonita connector to exchange the code
    success = call_bonita_connector(auth_code)

    if success:
        print("\n" + "=" * 80)
        print("NEXT STEPS:")
        print("=" * 80)
        print("\nThe access token can now be used to make authenticated API calls.")
        print("\nExample for Gmail API:")
        print("  curl -H \"Authorization: Bearer <TOKEN>\" \\")
        print("       https://gmail.googleapis.com/gmail/v1/users/me/messages")
        print("\nNote: The token will be cached by the connector for subsequent requests")
        print("until it expires (typically 1 hour for Google tokens).")
        print()
    else:
        print("\n" + "=" * 80)
        print("TROUBLESHOOTING:")
        print("=" * 80)
        print("\nIf the connector failed, check:")
        print("  1. Authorization code hasn't been used before (codes are single-use)")
        print("  2. Authorization code hasn't expired (typically 10 minutes)")
        print("  3. CLIENT_ID and CLIENT_SECRET are correct")
        print("  4. Redirect URI matches the one configured in Google Cloud Console")
        print("  5. Maven build completed successfully (run ./mvnw clean install)")
        print()

if __name__ == "__main__":
    main()
