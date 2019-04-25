# jwt-auth
jwt-auth is a WordPress plugin that enables authentication using [JSON Web Tokens](https://jwt.io). This plugin will be proposed as an addition to WordPress Core in the near future.

## Getting Started

This plugin isn't currently listed in the WordPress Plugin Directory. Therefore, you'll need to install it manually. You can do this by [downloading the latest code](https://github.com/WP-API/jwt-auth/archive/develop.zip) and uploading it to your site.

### How it works

At a high level, JSON Web Tokens work by exchanging a valid username and password for a long-lived token. This token can then be used to authenticate requests, making it unnecessary to store and repeatedly transmit usernames and passwords. 

#### Retrieving a Token

In order to receive a token, you must authenticate the user.  This can be done with a request that looks like:

```bash
curl -X "POST" "https://{my-domain-name}/wp-json/wp/v2/token/" \
     -H 'Content-Type: application/x-www-form-urlencoded; charset=utf-8' \
     --data-urlencode "username=my-username" \
     --data-urlencode "password=my-password"
```

This will return a response that looks like:

```javascript
{
  "access_token": "eyJ0eXAi[...]",
  "data": {
    "user": {
      "id": 1,
      "type": "wp_user",
      "user_login": "my-username",
      "user_email": "my-email-address@example.com"
    }
  }
}
```

The `access_token` field is what you'll use for subsequent requests. For example, to fetch the user data, you could perform a request like:

```bash
curl "https://{my-domain-name}/wp-json/wp/v2/users/me" \
     -H 'Authorization: Bearer eyJ0eXAi[...]'
```

> Note that the header reads `Bearer { token }`. Ensure you include the word "Bearer" (with a space after it) in order to be properly authenticated.

## Contributing

We'd love help with this project! The best way to get involved is to reach out via the #core-restapi channel in [Slack](https://make.wordpress.org/chat/).

## License

jwt-auth is licensed under [GNU General Public License v2](https://github.com/WP-API/jwt-auth/blob/develop/LICENSE).
