# Implement this

to do list

# Protecting Frontend-Only Routes Like Resources

You've identified an important security gap: the Resources page is frontend-only with no backend validation. Without backend protection, it can indeed be bypassed.

## Why This Is a Security Issue

As we discussed, your frontend protection (ProtectedRoute.js) can be bypassed by:
- Manipulating the Redux store
- Editing code in DevTools
- Direct API calls

## Solutions to Protect the Resources Page

1. **Add Backend API for Resources Data**:
   - Create a new `/resources` endpoint in Flask
   - Move resource data from frontend to backend
   - Apply subscription_check to this endpoint
   ```python
   # Add this to protected_prefixes in subscription_check.py
   '/resources',
   ```

2. **Add Backend Validation Endpoint**:
   - Create a simple `/validate-access/resources` endpoint
   - Make your Resources page call this on load
   - Return 403 if no subscription
   - Frontend shows error message if validation fails

3. **Dynamic Content Loading**:
   - Keep resource links in backend database
   - Only load actual content after subscription check

## Example Implementation (Backend)

```python
# Create a new file: backend/routes/resources_routes.py
from flask import Blueprint, jsonify, request
from models.test import get_user_by_id

resources_bp = Blueprint('resources', __name__)

@resources_bp.route('/resources', methods=['GET'])
def get_resources():
    user_id = request.args.get('userId')
    
    # Validate user has subscription
    user = get_user_by_id(user_id)
    if not user or not user.get('subscriptionActive'):
        return jsonify({'error': 'Subscription required'}), 403
    
    # Return resources data
    resources = [
        {"title": "Study Guide", "url": "/resources/study-guide"},
        {"title": "Practice Exam", "url": "/resources/practice-exam"}
        # More resources
    ]
    
    return jsonify(resources)
```

Then register it in app.py and add it to protected_prefixes.

This approach ensures that even if someone bypasses your frontend protection, they still can't access the actual resources data without a valid subscription.


-----

Fix theme iniliation being the same for the browser and anything else liek that

----
# Implment rate limiting for login, register, and contact form
------
# Figure out the discrepancy in the support page and how it gathers a user id or whatver idk
