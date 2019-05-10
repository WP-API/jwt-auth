=== JWT Auth ===
Contributors: valendesigns
Tags: jwt, json-web-token, auth, authentication, rest, wp-rest, api, wp-api, json, wp-json
Requires at least: 5.2
Tested up to: 5.2
Stable tag: 0.1.0
License: GPLv2 or later
License URI: http://www.gnu.org/licenses/gpl-2.0.html
Requires PHP: 5.6.20

Enable JSON Web Token authentication for the WordPress REST API.

== Description ==

This plugin makes it possible to use a JSON Web Token (JWT) to securely authenticate a valid user requesting access to
your WordPress REST API resources.

JSON Web Tokens are an open, industry standard [RFC 7519](https://tools.ietf.org/html/rfc7519) method for representing
claims securely between two parties.

== Installation ==

This plugin is not currently listed in the WordPress Plugin Directory. You'll need to install it manually.

1. [Download](https://github.com/WP-API/jwt-auth/archive/develop.zip) the latest version of the `jwt-auth` plugin.
1. Go to Plugins > Add New.
1. Click Upload Plugin to display the WordPress Plugin upload field.
1. Click Choose File to navigate your local file directory.
1. Select the WordPress Plugin zip archive you wish to upload and install.
1. Click Install Now to install the WordPress Plugin.
1. The resulting installation screen will list the installation as successful or note any problems during the install.
1. If successful, click Activate Plugin to activate it, or Return to Plugin Installer for further actions.

== Generate Tokens ==

In order to generate an access and refresh token, you must be an authenticate user. There are a couple ways to
authenticate a user, but only one works for tokens.

When generating a token we must authenticate with what is called an application password. This allows us to invalidate
both the access token and refresh token by adding the API key to the tokens private claim. This ensures that when a
token is used that has a valid API key it will authenticate the request, but if the key has been revoked the token
becomes invalidated and cannot authenticate access to the request.

Application passwords protect us from the threat of long-lived tokens. Tokens are never stored on a server anywhere,
and they work until they expire, which could be filtered to be a long time from now. So what we do is decoded the token
and look for our safe and revocable application password inside the private claim. And since an application password
cannot be used to login to WordPress, it only exists to generate tokens, we now have a secure separation of access and
authentication.

If you try to generate a token with you username and password:

```bash
curl -X POST https://example.org/wp-json/wp/v2/token \
	-F username=admin \
	-F password=password
```

You should see an error like this:

```javascript
{
    "code": "rest_authentication_required_api_key_secret",
    "message": "An API key-pair is required to generate a token.",
    "data": {
        "status": 403
    }
}
```

Now with an application password:

```bash
curl -X POST https://example.org/wp-json/wp/v2/token \
	-F api_key=12345ascde \
	-F api_secret=54321edcba
```

You should see something like this:

```javascript
{
    "access_token": "YOUR_ACCESS_TOKEN",
    "data": {
        "user": {
            "id": 1,
            "type": "wp_user",
            "user_login": "admin",
            "user_email": "admin@sample.org",
            "api_key": "12345ascde"
        }
    },
    "exp": 604800,
    "refresh_token": "YOUR_REFRESH_TOKEN"
}
```

The `access_token` field is what you'll use for subsequent requests. For example, to fetch the user data, you could
perform a request like:

```bash
curl -X GET https://sample.org/wp-json/wp/v2/users/1 \
	-H 'Authorization: Bearer YOUR_ACCESS_TOKEN'
```

> Note that the header reads `Bearer YOUR_ACCESS_TOKEN`. Ensure you include the word "Bearer" (with a space after it)
in order to be properly authenticated.

Now the `refresh_token` field is a special kind of token that can be used to obtain a renewed access token when it
finally expires.

That request would be like this:

```bash
curl -X POST https://example.org/wp-json/wp/v2/token \
	-F refresh_token=YOUR_REFRESH_TOKEN
```

You can also check if the token is still valid and when it expires:

```bash
curl -X GET https://sample.org/wp-json/wp/v2/token/validate \
	-H 'Authorization: Bearer YOUR_ACCESS_TOKEN'
```

```javascript
{
    "code": "rest_authentication_valid_access_token",
    "message": "Valid access token.",
    "data": {
        "status": 200,
        "exp": 604800
    }
}
```

== Generate Key-pairs ==

In order to generate a token you first need to create an application password, or what we also refer to as a key-pair.
To create a key-pair you have to first log into the WordPress administrative panel and go to your profile page. There
you will see a section that gives you the ability to generate a named key-pair, download the key-pair, and generate
and download new tokens, as well.

By ensuring only users that can login to WordPress can create a key-pair and only key-pairs can generate tokens we get
all the benefits of implementing other security systems like 2factor authentication to secure users and don't have to
worry about defending that side of the user authentication flow.

== Contributing ==

Contributors Welcome! The best way to get involved is to reach out via the [#core-restapi](https://wordpress.slack.com/messages/core-restapi/) channel in [Slack](https://make.wordpress.org/chat/). Meetings are held weekly [Thursdays @ 06:00 UTC](https://www.timeanddate.com/worldclock/timezone/utc).

== License ==

`jwt-auth` is licensed under [GNU General Public License v2](/LICENSE)
