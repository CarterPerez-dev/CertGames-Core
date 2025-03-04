Below is a straightforward example of how you could integrate OAuth-based “Sign in with Apple,” “Sign in with Google,” etc., into your existing Flask backend. The approach below uses **Authlib** (a popular Python library for OAuth and OpenID Connect). You can adapt the same pattern for any provider (Google, Apple, GitHub, LinkedIn, etc.) as long as you have client credentials from the provider.

---

## 1. Install Dependencies

Make sure you have `authlib` installed. For example:

```bash
pip install authlib
```

Add this to your `requirements.txt` if it’s not already present:
```
authlib==1.2.0
```

---

## 2. Create a New File (e.g., `routes/oauth_routes.py`)

Here, we’ll create a dedicated blueprint for OAuth flows. We’ll show Google and Apple as examples. The logic is basically the same for other providers (just change the endpoints, scopes, user-info fields, etc.). 

**Key Points**:
1. We configure Authlib with the client IDs/secrets for each provider.
2. We define two main routes per provider:
   - A **login** (or “authorize”) route that redirects the user to the external OAuth page.
   - A **callback** route that handles the provider's response, obtains user profile info, and logs the user in.

Below is a **complete** example. Just drop it into your code, e.g., in `routes/oauth_routes.py`.

```python
#############################
# routes/oauth_routes.py
#############################
import os
from flask import Blueprint, request, redirect, url_for, session, jsonify
from authlib.integrations.flask_client import OAuth
from mongodb.database import db
from models.test import create_user, get_user_by_id
from bson import ObjectId
from datetime import datetime

oauth_bp = Blueprint('oauth_bp', __name__)

# Use Authlib’s OAuth registry
# Typically, you’d do this once in app.py and pass it around.
# For demonstration, we create it here in the blueprint:
oauth = OAuth()

#####################
# 1) CONFIGURE CLIENTS
#####################

# GOOGLE
google_client_id = os.environ.get("GOOGLE_CLIENT_ID")
google_client_secret = os.environ.get("GOOGLE_CLIENT_SECRET")
oauth.register(
    name='google',
    client_id=google_client_id,
    client_secret=google_client_secret,
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={
        'scope': 'openid email profile'
    }
)

# APPLE
apple_client_id = os.environ.get("APPLE_CLIENT_ID")
apple_client_secret = os.environ.get("APPLE_CLIENT_SECRET")
# Apple’s config is a bit more involved because you have to sign the client secret with a private key.
# In practice, you might use a separate function to generate the client_secret on the fly.
# For simplicity, assume we have pre-generated an Apple JWT as `apple_client_secret`.
oauth.register(
    name='apple',
    client_id=apple_client_id,
    client_secret=apple_client_secret,
    api_base_url='https://appleid.apple.com',
    access_token_url='https://appleid.apple.com/auth/token',
    authorize_url='https://appleid.apple.com/auth/authorize',
    client_kwargs={
        'scope': 'name email',      # Apple usually requires `name email`
        'response_mode': 'form_post' # Apple often requires form_post
    }
)

##########################################################################
# HELPER: CREATE OR FETCH USER FROM OAUTH PROFILE
##########################################################################
def find_or_create_oauth_user(provider_name, sub, email=None, name=None):
    """
    1) Look for existing user with matching `oauthAccounts`:
       e.g. a user doc might have { "oauthAccounts": [ {provider:'google', sub:'abcd1234'} ] } 
    2) If not found, see if there's a user with the same email. If found, attach this OAuth account to them.
    3) Otherwise, create a brand new user doc.
    4) Return that user doc.
    """
    users_coll = db.mainusers

    # 1) Check if user with that exact provider + sub
    existing = users_coll.find_one({
        "oauthAccounts": {
            "$elemMatch": {
                "provider": provider_name,
                "sub": sub
            }
        }
    })
    if existing:
        return existing

    # 2) Not found by sub? Maybe user with same email
    if email:
        existing_email_user = users_coll.find_one({"email": email.lower()})
        if existing_email_user:
            # Attach this provider info
            users_coll.update_one(
                {"_id": existing_email_user["_id"]},
                {
                    "$push": {
                        "oauthAccounts": {
                            "provider": provider_name,
                            "sub": sub,
                            "linkedAt": datetime.utcnow()
                        }
                    }
                }
            )
            return users_coll.find_one({"_id": existing_email_user["_id"]})

    # 3) If we get here, brand new user
    #    We'll do minimal fields; you can adapt to match your create_user function
    new_user_doc = {
        "username": name if name else f"{provider_name}_{sub[:6]}",
        "email": email.lower() if email else None,
        "password": None,  # if you want to leave local password blank
        "createdAt": datetime.utcnow(),
        "oauthAccounts": [
            {
                "provider": provider_name,
                "sub": sub,
                "linkedAt": datetime.utcnow()
            }
        ],
        # Additional fields from your code’s defaults:
        "coins": 0,
        "xp": 0,
        "level": 1,
        "achievements": [],
        "subscriptionActive": False,
        # etc.
    }
    inserted_id = users_coll.insert_one(new_user_doc).inserted_id
    return users_coll.find_one({"_id": inserted_id})


######################################################################
# 2) GOOGLE SIGN IN
######################################################################
@oauth_bp.route("/login/google", methods=["GET"])
def login_google():
    """
    1) Redirect user to Google’s OAuth flow
    2) When authorized, user is sent back to /auth/google/callback
    """
    redirect_uri = url_for("oauth_bp.google_callback", _external=True)
    return oauth.google.authorize_redirect(redirect_uri)


@oauth_bp.route("/auth/google/callback", methods=["GET", "POST"])
def google_callback():
    """
    Google's OAuth 2 callback
    """
    token = oauth.google.authorize_access_token()
    # token now has keys like id_token, access_token, etc.

    userinfo = token.get("userinfo")
    # if you used 'openid email profile', userinfo is typically under token['userinfo'],
    # or you might fetch from oauth.google.userinfo()

    if not userinfo:
        return jsonify({"error": "No userinfo returned from Google"}), 400

    sub = userinfo["sub"]
    email = userinfo.get("email")
    name = userinfo.get("name", "")

    # Store or find user
    user = find_or_create_oauth_user("google", sub, email, name)

    # “Log in” by storing in session
    session["userId"] = str(user["_id"])
    return redirect("/profile")  # or wherever you want them to land


######################################################################
# 3) APPLE SIGN IN
######################################################################
@oauth_bp.route("/login/apple", methods=["GET"])
def login_apple():
    """
    1) Redirect user to Apple’s sign in
    2) Apple will post back to /auth/apple/callback
    """
    redirect_uri = url_for("oauth_bp.apple_callback", _external=True)
    return oauth.apple.authorize_redirect(redirect_uri)


@oauth_bp.route("/auth/apple/callback", methods=["GET","POST"])
def apple_callback():
    """
    Apple callback route. Usually Apple does a POST callback w/ 'code' + 'id_token' 
    """
    token = oauth.apple.authorize_access_token()
    # token should have 'id_token' we can decode to get user info
    id_token = token.get("id_token")

    claims = oauth.apple.parse_id_token(token)
    # claims now typically contains "sub", "email", "email_verified", etc.

    sub = claims["sub"]
    email = claims.get("email")
    # Apple may or may not provide "name" depending on user settings
    # If not provided, we can store a placeholder or “private_apple_user”
    name = "AppleUser"

    # Create/find user
    user = find_or_create_oauth_user("apple", sub, email, name)

    # Log in
    session["userId"] = str(user["_id"])
    return redirect("/profile")  # or your front-end route

```

### Explanation of Key Parts

1. **`oauth = OAuth()`**: We instantiate Authlib’s `OAuth` registry.
2. **`oauth.register(...)`**: For each provider (Google, Apple, etc.), we add them with `client_id` and `client_secret`. 
   - Google can auto-discover the endpoints from `.well-known/openid-configuration`.
   - Apple requires your credentials and a slightly different flow.
3. **`login_*` routes**: e.g., `/login/google` => starts the OAuth flow by redirecting to Google.
4. **`callback` routes**: e.g., `/auth/google/callback` => handles the response. 
   - We call `authorize_access_token()` to exchange the code for tokens and user info.
   - We then parse the user’s email, unique ID (`sub`), name, etc.
5. **`find_or_create_oauth_user`**: Generic function that:
   - Looks for an existing user that already has `oauthAccounts.provider = google` and `sub = <theirs>`.
   - If not found, tries matching by email. If matched, attaches the new OAuth sub to that user’s record.
   - Otherwise, creates a brand new user document in `mainusers_collection`.

That means you keep your local user documents in the same place (`mainusers_collection`) but store a list of OAuth identities in e.g. `oauthAccounts = [ {provider:'google', sub:'...'}, {provider:'apple', sub:'...'} ]`. This way the same user can link multiple providers if you wish.

---

## 3. Integrate Into `app.py`

1. **Register the new blueprint** in `app.py`:

```python
from routes.oauth_routes import oauth_bp

def create_app():
    app = Flask(__name__)
    # ... your existing setup ...
    app.register_blueprint(oauth_bp, url_prefix="/oauth")
    # ...
    return app
```

So you’ll have routes like:
- `GET /oauth/login/google`
- `GET/POST /oauth/auth/google/callback`
- `GET /oauth/login/apple`
- `GET/POST /oauth/auth/apple/callback`

2. **Add Environment Variables**: In your `.env`:

```
GOOGLE_CLIENT_ID=your_google_app_client_id
GOOGLE_CLIENT_SECRET=your_google_app_secret
APPLE_CLIENT_ID=your_apple_service_id
APPLE_CLIENT_SECRET=the_signed_jwt_or_private_key
```

And ensure they’re loaded with `load_dotenv()`.

3. **Add the “Remember Me” Step** in the session code: 
   - We do `session["userId"] = str(user["_id"])`. 
   - On the front end, you can check that `session['userId']` exists, or do `/test/user/<user_id>` calls to confirm the user.

---

## 4. Frontend Adjustments

- **Buttons**: On your frontend (e.g., React), you’d add “Sign in with Google” and “Sign in with Apple” buttons. 
- **Click Handler**: They can simply do a GET request to your `/oauth/login/google` or open a new window. Example:

  ```js
  // e.g. handleGoogleLogin
  function handleGoogleLogin() {
    window.location.href = "/oauth/login/google";
  }

  // e.g. handleAppleLogin
  function handleAppleLogin() {
    window.location.href = "/oauth/login/apple";
  }
  ```

- **Flow**: The user is redirected to Google/Apple, they accept. The provider calls back to `/oauth/auth/<provider>/callback`. That route sets `session["userId"]`. Then you can redirect them to your profile page or a success screen.

---

## 5. Handling Existing Users & Edge Cases

- If a user attempts to log in with Apple, but we see the same email is already in use by a password-based account, we can unify them. The `find_or_create_oauth_user()` method above merges them by email. 
- If Apple or Google returns no email (some providers let the user hide it), you might create a new user with a dummy email, or prompt them to supply one on the frontend.

---

## 6. Optional: Protecting Routes

- In your existing routes, if you check `session['userId']`, it’ll now exist whether they logged in with username/password or with Google/Apple. So it’s the same approach as your normal `/test/login` route: if `session['userId']` is set, the user is “logged in.”

---

## 7. Summary

1. **Install** `authlib`.
2. **Set** environment variables for each provider’s credentials.
3. **Create** an OAuth blueprint with:
   - `login_{provider}()` route to redirect user.
   - `{provider}_callback()` route to handle the provider’s response.
   - A helper function to unify or create user records.
4. **Register** the blueprint in `app.py`.
5. **Add** front-end buttons to direct the user to `/oauth/login/<provider>`.
6. **Session** logic remains the same as your password-based flow.

That’s it! You now have a complete, working pattern for handling Google, Apple, or any other OAuth/OpenID provider. Once the user is authenticated, you’re storing them in `session['userId']`, which is precisely how the rest of your backend code currently checks for an authenticated user.
