# Implement this

to do list

# Xcode IOs app tetsing sacreen sizes
---
# remove audit logs after xzy amoutn of time, and audit logs or liek basically check if they and when they get removed
----
# Implment rate limiting for login, register, and contact form
------
# Figure out the discrepancy in the support page and how it gathers a user id or whatver idk
---
# do i import auth naviagors fro the SafeAreaprovider/ const { width, height } = Dimensions.get('window'); liek fro auth screens?


# web app
--
# organize backend ffiles-- also delete fluff
## split up test routes sinto multile route files and test models into multipel model files
## undsertadn core abailty/use of each backedn file and frotnend file
## delete anything not used
## delete all unused images liek with tools
--
# fix expired susbciptrion redirect loop issue
--
# fix npm vulnerabilties
--
# oracle, mondodb, google search, 
--
# set up mongo, sendgrid, admin dashbaord (i liek ouath for admin dashbaord) and maueb eevn seperate logic in admin dashbaord etc
--
# performance dashbaord-- links to all tools, ouath, more uses- accurat eubscriptions etc tec
##  ouath
##  have a real time handling request logs make sure to rate limit just in case of ddos and data deleition after xyz amoutn fo time
## susbcription management and data on like when a user sucbribed etc
## check datasbe fro useful info
## web viutals condensed into one giant average of speed/vitals
## have links to all your tools liek mongobd, sendgrid, oracle etc
-- 
# delete databse colelctiosn that arent used to reduce clutrter an confusiuoin
--

----
# About Your Temporary Registration Scenario
Yes, your understanding is correct! This is indeed a potential race condition in your system:

User1 enters registration info (stored temporarily) and sits on the subscription page
User2 enters identical registration info on another device
User2 subscribes, creating a permanent account with those credentials
User1 finally tries to subscribe, but now gets "username or email already taken"

This could theoretically happen because your registration screen likely only validates against permanent records in the database, not temporary registration data.
Standard solutions to this problem would be:

Adding a short expiration time for temporary registration data (24 hours is common)
Adding a session identifier to temporary data so it's tied to the specific device/browser
-----
# make an EVNTUALLY file wehre we do optionla imporvemnst down the line- such as 

```python
# Install the official Apple library
# pip install appstoreserverlibrary

from appstoreserverlibrary.signed_data_verifier import SignedDataVerifier

# In your webhook handler
def apple_server_notification():
    try:
        signed_data_verifier = SignedDataVerifier()
        signed_payload = request.json.get("signedPayload")
        
        decoded_payload = signed_data_verifier.verify_and_decode_notification(signed_payload)
        
        # Continue processing based on notification type
        # ...
        
    except Exception as e:
        current_app.logger.error(f"Error processing Apple notification: {str(e)}")
```
