Below is one straightforward way to unify the “ignore leading/trailing spaces but disallow any embedded spaces” rule for both **username** and **password** fields—so that:

1. **Leading/trailing whitespace** is trimmed off (so `" carter "` becomes `"carter"`).
2. **Any space in the middle** is disallowed (so `"carter perez"` fails validation).

You already have a pattern check for usernames (`^[A-Za-z0-9._-]+$`) that rejects spaces in the middle. For passwords, the registration code disallows whitespace via a `/[ \t\r\n<>]/` test, but the login password checks are more lenient. Below are minimal edits to each file so that both registration and login consistently **trim** the input and then **disallow** mid-string spaces.

---

## 1) **`Login.js`**: Trim inputs and unify password checks

**Key change**: Right before validations, trim `usernameOrEmail` and `password`. Pass those trimmed values into the validations. Then inside `validatePassword`, disallow any `\s`:

```diff
// src/components/pages/auth/Login.js

function validatePassword(pwd) {
+  // Trim it first
+  const trimmedPwd = pwd.trim();
  const errors = [];

- if (!pwd) {
+ if (!trimmedPwd) {
    errors.push("Password cannot be empty.");
    return errors;
  }
- if (pwd.length < 6) {
+ if (trimmedPwd.length < 6) {
    errors.push("Password must be at least 6 characters.");
  }

+ // Disallow *any* spaces in the middle after trimming
+ // (leading/trailing are gone, so any remaining space is "embedded")
+ if (/\s/.test(trimmedPwd)) {
+   errors.push("Password cannot contain spaces.");
+ }

  if (COMMON_PASSWORDS.has(trimmedPwd.toLowerCase())) {
    errors.push("Password is too common. Please choose a stronger one.");
  }
  return errors;
}

export const Login = () => {
  ...
  const handleSubmit = (e) => {
    e.preventDefault();

+   const trimmedIdentifier = usernameOrEmail.trim();
+   const trimmedPassword   = password.trim();

    const errors = [];
-   errors.push(...validateLoginIdentifier(usernameOrEmail));
-   errors.push(...validatePassword(password));
+   errors.push(...validateLoginIdentifier(trimmedIdentifier));
+   errors.push(...validatePassword(trimmedPassword));

    if (errors.length > 0) {
      ...
      return;
    }

    dispatch(loginUser({ 
-     usernameOrEmail, 
-     password 
+     usernameOrEmail: trimmedIdentifier,
+     password: trimmedPassword
    }))
      ...
  };

  return (
    ...
  );
};
```

### Explanation

- We do `pwd.trim()` inside **`validatePassword`** so that any user-typed leading/trailing spaces are dropped. If anything remains (like `"  my pass  "` → `"my pass"`), it fails on the embedded space check.  
- Similarly, in **`handleSubmit`**, we trim the identifier (`usernameOrEmail`) so that logging in with `"  carter  "` will effectively log in as `"carter"`, while `"carter perez"` remains invalid because the embedded space fails the username pattern check in `validateLoginIdentifier`.

---

## 2) **`Register.js`**: Trim everything and keep the strict “no spaces in password” rule

You’re already disallowing spaces for passwords (via `/[ \t\r\n<>]/`), so we’ll just ensure we do a `.trim()` before we do any checks. Also do the same for username and email:

```diff
// src/components/pages/auth/Register.js

function validatePassword(password, username, email) {
+  const trimmedPwd = password.trim();
  const errors = [];
- if (password.length < 6 || password.length > 69) {
+ if (trimmedPwd.length < 6 || trimmedPwd.length > 69) {
    errors.push("Password must be between 6 and 69 characters long.");
  }
- if (/[ \t\r\n<>]/.test(password)) {
+ if (/[ \t\r\n<>]/.test(trimmedPwd)) {
    errors.push("Password cannot contain whitespace or < or > characters.");
  }

  // Then the rest of your checks just use trimmedPwd...
  if (!/[A-Z]/.test(trimmedPwd)) {
    errors.push("Password must contain at least one uppercase letter.");
  }
  ...
  return errors;
}

const Register = () => {
  ...
  const handleSubmit = async (e) => {
    e.preventDefault();

+   const trimmedUsername  = username.trim();
+   const trimmedEmail     = email.trim();
+   const trimmedPassword  = password.trim();
+   const trimmedConfirm   = confirmPassword.trim();

    let allErrors = [];
-   allErrors.push(...validateUsername(username));
-   allErrors.push(...validateEmail(email));
-   allErrors.push(...validatePassword(password, username, email));
-   if (password !== confirmPassword) {
+   allErrors.push(...validateUsername(trimmedUsername));
+   allErrors.push(...validateEmail(trimmedEmail));
+   allErrors.push(...validatePassword(trimmedPassword, trimmedUsername, trimmedEmail));
+   if (trimmedPassword !== trimmedConfirm) {
      allErrors.push("Passwords do not match.");
    }

    if (allErrors.length > 0) {
      ...
      return;
    }

    try {
      const result = await dispatch(
-       registerUser({ username, email, password, confirmPassword })
+       registerUser({ 
+         username: trimmedUsername, 
+         email:    trimmedEmail, 
+         password: trimmedPassword, 
+         confirmPassword: trimmedConfirm 
+       })
      );
      ...
      // Optionally auto-login:
-     const loginRes = await dispatch(loginUser({ usernameOrEmail: username, password }));
+     const loginRes = await dispatch(loginUser({ 
+       usernameOrEmail: trimmedUsername, 
+       password: trimmedPassword 
+     }));
      ...
    } catch (err) {
      ...
    }
  };

  return (
    ...
  );
};
```

### Explanation

- By trimming `username`, `email`, and `password` first, any leading/trailing spaces are silently removed.  
- If the user typed embedded spaces (`"my pass"`), the same whitespace check will fail validation.  
- Ensures that `"  carter  "` is stored as `"carter"`, `"  email@domain.com  "` becomes `"email@domain.com"`, etc.

---

## 3) **`userProfile.js`** (Settings changes for username/email/password)

Wherever the user changes username/email/password, do the same: trim input before sending to your backend or before local validation:

```diff
// src/components/pages/store/UserProfile.js

function frontValidateUsername(username) {
+  const name = username.trim().normalize("NFC");
   const errors = [];
-  // remove the original line: const name = username.normalize("NFC");
   ...
}

function frontValidatePassword(password, username, email) {
+  const pwd = password.trim();
   const errors = [];
   ...
   // same logic. If you want to forbid spaces:
   if (/[ \t\r\n<>]/.test(pwd)) {
     errors.push("Password cannot contain whitespace or < or > characters.");
   }
   ...
}

const UserProfile = () => {
  ...
  const handleChangeUsername = async () => {
    ...
+   const trimmedUsername = newUsername.trim();
    const errors = frontValidateUsername(trimmedUsername);
    if (errors.length > 0) {
      ...
    }
    try {
      const res = await fetch('/api/test/user/change-username', {
        ...
        body: JSON.stringify({ userId, newUsername: trimmedUsername })
      });
      ...
    } catch (err) {
      ...
    }
  };

  const handleChangeEmail = async () => {
    ...
+   const trimmedEmail = newEmail.trim();
    const errors = frontValidateEmail(trimmedEmail);
    ...
    try {
      const res = await fetch('/api/test/user/change-email', {
        ...
        body: JSON.stringify({ userId, newEmail: trimmedEmail })
      });
      ...
    } catch (err) {
      ...
    }
  };

  const handleChangePassword = async () => {
    ...
+   const oldPwd = oldPassword.trim();
+   const newPwd = newPassword.trim();
+   const confirmPwd = confirmPassword.trim();

    if (!oldPwd || !newPwd || !confirmPwd) {
      ...
    }
    if (newPwd !== confirmPwd) {
      ...
    }

    const errors = frontValidatePassword(newPwd, username, email);
    ...
    try {
      const res = await fetch('/api/test/user/change-password', {
        ...
        body: JSON.stringify({
          userId,
-         oldPassword,
-         newPassword,
-         confirmPassword
+         oldPassword: oldPwd,
+         newPassword: newPwd,
+         confirmPassword: confirmPwd
        })
      });
      ...
    } catch (err) {
      ...
    }
  };
  ...
};
```

### Explanation

- Whenever the user updates their username/email/password from the profile settings, do the same trimming so that a user cannot sneak in leading/trailing spaces. If they type spaces in the middle, they’ll fail the same pattern check.

---

## 4) **(Optionally) Server-Side**: Also `.strip()` (Python) or `.trim()` (Node) for Safety

Even though the above front-end changes are typically enough, it’s always wise to do a final `.strip()` / `.replace()` on the server side. This ensures if someone bypasses the front end (e.g. Postman calls), the server still cleans up leading/trailing whitespace. For example, in Python:

```python
def register_user_api():
    username = request.json.get('username', '').strip()
    email = request.json.get('email', '').strip()
    password = request.json.get('password', '')

    # If you want to remove middle spaces from password entirely 
    # or disallow them, do the check or replacement here:
    # password = password.strip() # at least remove leading/trailing 
    # if ' ' in password: # if you want to disallow
    #     return {"error": "Spaces not allowed in password."}, 400

    # ... proceed with the rest ...
```

That way your backend is consistent with the same trimming rules. But at minimum, the front end changes above will achieve the behavior you described.

---

## Final Summary

1. **Trim** username/email/password right after the user types them (leading/trailing spaces vanish).  
2. **Disallow** any spaces that remain in the middle by pattern checks (for username) or explicit `if (/\s/.test(...)) { ... }` for passwords.  
3. Pass these trimmed values to your Redux `loginUser` / `registerUser` / etc.  
4. (Optionally) do the same `.strip()` on the back end for perfect consistency.

With these small patches, your app will:

- Ignore any leading/trailing whitespace in usernames/emails/passwords.
- Fail validation if a user tries to insert spaces in the middle of usernames or passwords.  
