# api documentation for  [oauth (v0.9.15)](https://github.com/ciaranj/node-oauth#readme)  [![npm package](https://img.shields.io/npm/v/npmdoc-oauth.svg?style=flat-square)](https://www.npmjs.org/package/npmdoc-oauth) [![travis-ci.org build-status](https://api.travis-ci.org/npmdoc/node-npmdoc-oauth.svg)](https://travis-ci.org/npmdoc/node-npmdoc-oauth)
#### Library for interacting with OAuth 1.0, 1.0A, 2 and Echo.  Provides simplified client access and allows for construction of more complex apis and OAuth providers.

[![NPM](https://nodei.co/npm/oauth.png?downloads=true)](https://www.npmjs.com/package/oauth)

[![apidoc](https://npmdoc.github.io/node-npmdoc-oauth/build/screenCapture.buildNpmdoc.browser.%252Fhome%252Ftravis%252Fbuild%252Fnpmdoc%252Fnode-npmdoc-oauth%252Ftmp%252Fbuild%252Fapidoc.html.png)](https://npmdoc.github.io/node-npmdoc-oauth/build/apidoc.html)

![npmPackageListing](https://npmdoc.github.io/node-npmdoc-oauth/build/screenCapture.npmPackageListing.svg)

![npmPackageDependencyTree](https://npmdoc.github.io/node-npmdoc-oauth/build/screenCapture.npmPackageDependencyTree.svg)



# package.json

```json

{
    "author": {
        "name": "Ciaran Jessup",
        "email": "ciaranj@gmail.com"
    },
    "bugs": {
        "url": "https://github.com/ciaranj/node-oauth/issues"
    },
    "dependencies": {},
    "description": "Library for interacting with OAuth 1.0, 1.0A, 2 and Echo.  Provides simplified client access and allows for construction of more complex apis and OAuth providers.",
    "devDependencies": {
        "vows": "0.5.x"
    },
    "directories": {
        "lib": "./lib"
    },
    "dist": {
        "shasum": "bd1fefaf686c96b75475aed5196412ff60cfb9c1",
        "tarball": "https://registry.npmjs.org/oauth/-/oauth-0.9.15.tgz"
    },
    "gitHead": "a7f8a1e21c362eb4ed2039431fb9ac2ae749f26a",
    "homepage": "https://github.com/ciaranj/node-oauth#readme",
    "license": "MIT",
    "main": "index.js",
    "maintainers": [
        {
            "name": "ciaranj",
            "email": "ciaranj@gmail.com"
        }
    ],
    "name": "oauth",
    "optionalDependencies": {},
    "readme": "ERROR: No README data found!",
    "repository": {
        "type": "git",
        "url": "git+ssh://git@github.com/ciaranj/node-oauth.git"
    },
    "scripts": {
        "test": "make test"
    },
    "version": "0.9.15"
}
```



# <a name="apidoc.tableOfContents"></a>[table of contents](#apidoc.tableOfContents)

#### [module oauth](#apidoc.module.oauth)
1.  [function <span class="apidocSignatureSpan">oauth.</span>OAuth (requestUrl, accessUrl, consumerKey, consumerSecret, version, authorize_callback, signatureMethod, nonceSize, customHeaders )](#apidoc.element.oauth.OAuth)
1.  [function <span class="apidocSignatureSpan">oauth.</span>OAuth2 (clientId, clientSecret, baseSite, authorizePath, accessTokenPath, customHeaders)](#apidoc.element.oauth.OAuth2)
1.  [function <span class="apidocSignatureSpan">oauth.</span>OAuthEcho (realm, verify_credentials, consumerKey, consumerSecret, version, signatureMethod, nonceSize, customHeaders)](#apidoc.element.oauth.OAuthEcho)
1.  object <span class="apidocSignatureSpan"></span>oauth
1.  object <span class="apidocSignatureSpan">oauth.</span>OAuth.prototype
1.  object <span class="apidocSignatureSpan">oauth.</span>OAuth2.prototype
1.  object <span class="apidocSignatureSpan">oauth.</span>_utils
1.  object <span class="apidocSignatureSpan">oauth.</span>oauth2
1.  object <span class="apidocSignatureSpan">oauth.</span>sha1

#### [module oauth.OAuth](#apidoc.module.oauth.OAuth)
1.  [function <span class="apidocSignatureSpan">oauth.</span>OAuth (requestUrl, accessUrl, consumerKey, consumerSecret, version, authorize_callback, signatureMethod, nonceSize, customHeaders )](#apidoc.element.oauth.OAuth.OAuth)

#### [module oauth.OAuth.prototype](#apidoc.module.oauth.OAuth.prototype)
1.  [function <span class="apidocSignatureSpan">oauth.OAuth.prototype.</span>_buildAuthorizationHeaders (orderedParameters)](#apidoc.element.oauth.OAuth.prototype._buildAuthorizationHeaders)
1.  [function <span class="apidocSignatureSpan">oauth.OAuth.prototype.</span>_createClient ( port, hostname, method, path, headers, sslEnabled )](#apidoc.element.oauth.OAuth.prototype._createClient)
1.  [function <span class="apidocSignatureSpan">oauth.OAuth.prototype.</span>_createSignature (signatureBase, tokenSecret)](#apidoc.element.oauth.OAuth.prototype._createSignature)
1.  [function <span class="apidocSignatureSpan">oauth.OAuth.prototype.</span>_createSignatureBase (method, url, parameters)](#apidoc.element.oauth.OAuth.prototype._createSignatureBase)
1.  [function <span class="apidocSignatureSpan">oauth.OAuth.prototype.</span>_decodeData (toDecode)](#apidoc.element.oauth.OAuth.prototype._decodeData)
1.  [function <span class="apidocSignatureSpan">oauth.OAuth.prototype.</span>_encodeData (toEncode)](#apidoc.element.oauth.OAuth.prototype._encodeData)
1.  [function <span class="apidocSignatureSpan">oauth.OAuth.prototype.</span>_getNonce (nonceSize)](#apidoc.element.oauth.OAuth.prototype._getNonce)
1.  [function <span class="apidocSignatureSpan">oauth.OAuth.prototype.</span>_getSignature (method, url, parameters, tokenSecret)](#apidoc.element.oauth.OAuth.prototype._getSignature)
1.  [function <span class="apidocSignatureSpan">oauth.OAuth.prototype.</span>_getTimestamp ()](#apidoc.element.oauth.OAuth.prototype._getTimestamp)
1.  [function <span class="apidocSignatureSpan">oauth.OAuth.prototype.</span>_isParameterNameAnOAuthParameter (parameter)](#apidoc.element.oauth.OAuth.prototype._isParameterNameAnOAuthParameter)
1.  [function <span class="apidocSignatureSpan">oauth.OAuth.prototype.</span>_makeArrayOfArgumentsHash (argumentsHash)](#apidoc.element.oauth.OAuth.prototype._makeArrayOfArgumentsHash)
1.  [function <span class="apidocSignatureSpan">oauth.OAuth.prototype.</span>_normaliseRequestParams (args)](#apidoc.element.oauth.OAuth.prototype._normaliseRequestParams)
1.  [function <span class="apidocSignatureSpan">oauth.OAuth.prototype.</span>_normalizeUrl (url)](#apidoc.element.oauth.OAuth.prototype._normalizeUrl)
1.  [function <span class="apidocSignatureSpan">oauth.OAuth.prototype.</span>_performSecureRequest ( oauth_token, oauth_token_secret, method, url, extra_params, post_body, post_content_type, callback )](#apidoc.element.oauth.OAuth.prototype._performSecureRequest)
1.  [function <span class="apidocSignatureSpan">oauth.OAuth.prototype.</span>_prepareParameters ( oauth_token, oauth_token_secret, method, url, extra_params )](#apidoc.element.oauth.OAuth.prototype._prepareParameters)
1.  [function <span class="apidocSignatureSpan">oauth.OAuth.prototype.</span>_putOrPost (method, url, oauth_token, oauth_token_secret, post_body, post_content_type, callback)](#apidoc.element.oauth.OAuth.prototype._putOrPost)
1.  [function <span class="apidocSignatureSpan">oauth.OAuth.prototype.</span>_sortRequestParams (argument_pairs)](#apidoc.element.oauth.OAuth.prototype._sortRequestParams)
1.  [function <span class="apidocSignatureSpan">oauth.OAuth.prototype.</span>authHeader (url, oauth_token, oauth_token_secret, method)](#apidoc.element.oauth.OAuth.prototype.authHeader)
1.  [function <span class="apidocSignatureSpan">oauth.OAuth.prototype.</span>delete (url, oauth_token, oauth_token_secret, callback)](#apidoc.element.oauth.OAuth.prototype.delete)
1.  [function <span class="apidocSignatureSpan">oauth.OAuth.prototype.</span>get (url, oauth_token, oauth_token_secret, callback)](#apidoc.element.oauth.OAuth.prototype.get)
1.  [function <span class="apidocSignatureSpan">oauth.OAuth.prototype.</span>getOAuthAccessToken (oauth_token, oauth_token_secret, oauth_verifier, callback)](#apidoc.element.oauth.OAuth.prototype.getOAuthAccessToken)
1.  [function <span class="apidocSignatureSpan">oauth.OAuth.prototype.</span>getOAuthRequestToken ( extraParams, callback )](#apidoc.element.oauth.OAuth.prototype.getOAuthRequestToken)
1.  [function <span class="apidocSignatureSpan">oauth.OAuth.prototype.</span>getProtectedResource (url, method, oauth_token, oauth_token_secret, callback)](#apidoc.element.oauth.OAuth.prototype.getProtectedResource)
1.  [function <span class="apidocSignatureSpan">oauth.OAuth.prototype.</span>post (url, oauth_token, oauth_token_secret, post_body, post_content_type, callback)](#apidoc.element.oauth.OAuth.prototype.post)
1.  [function <span class="apidocSignatureSpan">oauth.OAuth.prototype.</span>put (url, oauth_token, oauth_token_secret, post_body, post_content_type, callback)](#apidoc.element.oauth.OAuth.prototype.put)
1.  [function <span class="apidocSignatureSpan">oauth.OAuth.prototype.</span>setClientOptions (options)](#apidoc.element.oauth.OAuth.prototype.setClientOptions)
1.  [function <span class="apidocSignatureSpan">oauth.OAuth.prototype.</span>signUrl (url, oauth_token, oauth_token_secret, method)](#apidoc.element.oauth.OAuth.prototype.signUrl)
1.  object <span class="apidocSignatureSpan">oauth.OAuth.prototype.</span>NONCE_CHARS

#### [module oauth.OAuth2](#apidoc.module.oauth.OAuth2)
1.  [function <span class="apidocSignatureSpan">oauth.</span>OAuth2 (clientId, clientSecret, baseSite, authorizePath, accessTokenPath, customHeaders)](#apidoc.element.oauth.OAuth2.OAuth2)

#### [module oauth.OAuth2.prototype](#apidoc.module.oauth.OAuth2.prototype)
1.  [function <span class="apidocSignatureSpan">oauth.OAuth2.prototype.</span>_chooseHttpLibrary ( parsedUrl )](#apidoc.element.oauth.OAuth2.prototype._chooseHttpLibrary)
1.  [function <span class="apidocSignatureSpan">oauth.OAuth2.prototype.</span>_executeRequest ( http_library, options, post_body, callback )](#apidoc.element.oauth.OAuth2.prototype._executeRequest)
1.  [function <span class="apidocSignatureSpan">oauth.OAuth2.prototype.</span>_getAccessTokenUrl ()](#apidoc.element.oauth.OAuth2.prototype._getAccessTokenUrl)
1.  [function <span class="apidocSignatureSpan">oauth.OAuth2.prototype.</span>_request (method, url, headers, post_body, access_token, callback)](#apidoc.element.oauth.OAuth2.prototype._request)
1.  [function <span class="apidocSignatureSpan">oauth.OAuth2.prototype.</span>buildAuthHeader (token)](#apidoc.element.oauth.OAuth2.prototype.buildAuthHeader)
1.  [function <span class="apidocSignatureSpan">oauth.OAuth2.prototype.</span>get (url, access_token, callback)](#apidoc.element.oauth.OAuth2.prototype.get)
1.  [function <span class="apidocSignatureSpan">oauth.OAuth2.prototype.</span>getAuthorizeUrl ( params )](#apidoc.element.oauth.OAuth2.prototype.getAuthorizeUrl)
1.  [function <span class="apidocSignatureSpan">oauth.OAuth2.prototype.</span>getOAuthAccessToken (code, params, callback)](#apidoc.element.oauth.OAuth2.prototype.getOAuthAccessToken)
1.  [function <span class="apidocSignatureSpan">oauth.OAuth2.prototype.</span>getProtectedResource (url, access_token, callback)](#apidoc.element.oauth.OAuth2.prototype.getProtectedResource)
1.  [function <span class="apidocSignatureSpan">oauth.OAuth2.prototype.</span>setAccessTokenName ( name )](#apidoc.element.oauth.OAuth2.prototype.setAccessTokenName)
1.  [function <span class="apidocSignatureSpan">oauth.OAuth2.prototype.</span>setAgent (agent)](#apidoc.element.oauth.OAuth2.prototype.setAgent)
1.  [function <span class="apidocSignatureSpan">oauth.OAuth2.prototype.</span>setAuthMethod ( authMethod )](#apidoc.element.oauth.OAuth2.prototype.setAuthMethod)
1.  [function <span class="apidocSignatureSpan">oauth.OAuth2.prototype.</span>useAuthorizationHeaderforGET (useIt)](#apidoc.element.oauth.OAuth2.prototype.useAuthorizationHeaderforGET)

#### [module oauth.OAuthEcho](#apidoc.module.oauth.OAuthEcho)
1.  [function <span class="apidocSignatureSpan">oauth.</span>OAuthEcho (realm, verify_credentials, consumerKey, consumerSecret, version, signatureMethod, nonceSize, customHeaders)](#apidoc.element.oauth.OAuthEcho.OAuthEcho)

#### [module oauth._utils](#apidoc.module.oauth._utils)
1.  [function <span class="apidocSignatureSpan">oauth._utils.</span>isAnEarlyCloseHost ( hostName )](#apidoc.element.oauth._utils.isAnEarlyCloseHost)

#### [module oauth.oauth](#apidoc.module.oauth.oauth)
1.  [function <span class="apidocSignatureSpan">oauth.oauth.</span>OAuth (requestUrl, accessUrl, consumerKey, consumerSecret, version, authorize_callback, signatureMethod, nonceSize, customHeaders )](#apidoc.element.oauth.oauth.OAuth)
1.  [function <span class="apidocSignatureSpan">oauth.oauth.</span>OAuthEcho (realm, verify_credentials, consumerKey, consumerSecret, version, signatureMethod, nonceSize, customHeaders)](#apidoc.element.oauth.oauth.OAuthEcho)

#### [module oauth.oauth2](#apidoc.module.oauth.oauth2)
1.  [function <span class="apidocSignatureSpan">oauth.oauth2.</span>OAuth2 (clientId, clientSecret, baseSite, authorizePath, accessTokenPath, customHeaders)](#apidoc.element.oauth.oauth2.OAuth2)

#### [module oauth.sha1](#apidoc.module.oauth.sha1)
1.  [function <span class="apidocSignatureSpan">oauth.sha1.</span>HMACSHA1 (key, data)](#apidoc.element.oauth.sha1.HMACSHA1)



# <a name="apidoc.module.oauth"></a>[module oauth](#apidoc.module.oauth)

#### <a name="apidoc.element.oauth.OAuth"></a>[function <span class="apidocSignatureSpan">oauth.</span>OAuth (requestUrl, accessUrl, consumerKey, consumerSecret, version, authorize_callback, signatureMethod, nonceSize, customHeaders )](#apidoc.element.oauth.OAuth)
- description and source-code
```javascript
OAuth = function (requestUrl, accessUrl, consumerKey, consumerSecret, version, authorize_callback, signatureMethod, nonceSize, customHeaders ) {
  this._isEcho = false;

  this._requestUrl= requestUrl;
  this._accessUrl= accessUrl;
  this._consumerKey= consumerKey;
  this._consumerSecret= this._encodeData( consumerSecret );
  if (signatureMethod == "RSA-SHA1") {
    this._privateKey = consumerSecret;
  }
  this._version= version;
  if( authorize_callback === undefined ) {
    this._authorize_callback= "oob";
  }
  else {
    this._authorize_callback= authorize_callback;
  }

  if( signatureMethod != "PLAINTEXT" && signatureMethod != "HMAC-SHA1" && signatureMethod != "RSA-SHA1")
    throw new Error("Un-supported signature method: " + signatureMethod )
  this._signatureMethod= signatureMethod;
  this._nonceSize= nonceSize || 32;
  this._headers= customHeaders || {"Accept" : "*/*",
                                   "Connection" : "close",
                                   "User-Agent" : "Node authentication"}
  this._clientOptions= this._defaultClientOptions= {"requestTokenHttpMethod": "POST",
                                                    "accessTokenHttpMethod": "POST",
                                                    "followRedirects": true};
  this._oauthParameterSeperator = ",";
}
```
- example usage
```shell
...
## OAuth1.0

'''javascript
describe('OAuth1.0',function(){
var OAuth = require('oauth');

it('tests trends Twitter API v1.1',function(done){
  var oauth = new OAuth.OAuth(
    'https://api.twitter.com/oauth/request_token',
    'https://api.twitter.com/oauth/access_token',
    'your application consumer key',
    'your application secret',
    '1.0A',
    null,
    'HMAC-SHA1'
...
```

#### <a name="apidoc.element.oauth.OAuth2"></a>[function <span class="apidocSignatureSpan">oauth.</span>OAuth2 (clientId, clientSecret, baseSite, authorizePath, accessTokenPath, customHeaders)](#apidoc.element.oauth.OAuth2)
- description and source-code
```javascript
OAuth2 = function (clientId, clientSecret, baseSite, authorizePath, accessTokenPath, customHeaders) {
  this._clientId= clientId;
  this._clientSecret= clientSecret;
  this._baseSite= baseSite;
  this._authorizeUrl= authorizePath || "/oauth/authorize";
  this._accessTokenUrl= accessTokenPath || "/oauth/access_token";
  this._accessTokenName= "access_token";
  this._authMethod= "Bearer";
  this._customHeaders = customHeaders || {};
  this._useAuthorizationHeaderForGET= false;

  //our agent
  this._agent = undefined;
}
```
- example usage
```shell
n/a
```

#### <a name="apidoc.element.oauth.OAuthEcho"></a>[function <span class="apidocSignatureSpan">oauth.</span>OAuthEcho (realm, verify_credentials, consumerKey, consumerSecret, version, signatureMethod, nonceSize, customHeaders)](#apidoc.element.oauth.OAuthEcho)
- description and source-code
```javascript
OAuthEcho = function (realm, verify_credentials, consumerKey, consumerSecret, version, signatureMethod, nonceSize, customHeaders) {
  this._isEcho = true;

  this._realm= realm;
  this._verifyCredentials = verify_credentials;
  this._consumerKey= consumerKey;
  this._consumerSecret= this._encodeData( consumerSecret );
  if (signatureMethod == "RSA-SHA1") {
    this._privateKey = consumerSecret;
  }
  this._version= version;

  if( signatureMethod != "PLAINTEXT" && signatureMethod != "HMAC-SHA1" && signatureMethod != "RSA-SHA1")
    throw new Error("Un-supported signature method: " + signatureMethod );
  this._signatureMethod= signatureMethod;
  this._nonceSize= nonceSize || 32;
  this._headers= customHeaders || {"Accept" : "*/*",
                                   "Connection" : "close",
                                   "User-Agent" : "Node authentication"};
  this._oauthParameterSeperator = ",";
}
```
- example usage
```shell
n/a
```



# <a name="apidoc.module.oauth.OAuth"></a>[module oauth.OAuth](#apidoc.module.oauth.OAuth)

#### <a name="apidoc.element.oauth.OAuth.OAuth"></a>[function <span class="apidocSignatureSpan">oauth.</span>OAuth (requestUrl, accessUrl, consumerKey, consumerSecret, version, authorize_callback, signatureMethod, nonceSize, customHeaders )](#apidoc.element.oauth.OAuth.OAuth)
- description and source-code
```javascript
OAuth = function (requestUrl, accessUrl, consumerKey, consumerSecret, version, authorize_callback, signatureMethod, nonceSize, customHeaders ) {
  this._isEcho = false;

  this._requestUrl= requestUrl;
  this._accessUrl= accessUrl;
  this._consumerKey= consumerKey;
  this._consumerSecret= this._encodeData( consumerSecret );
  if (signatureMethod == "RSA-SHA1") {
    this._privateKey = consumerSecret;
  }
  this._version= version;
  if( authorize_callback === undefined ) {
    this._authorize_callback= "oob";
  }
  else {
    this._authorize_callback= authorize_callback;
  }

  if( signatureMethod != "PLAINTEXT" && signatureMethod != "HMAC-SHA1" && signatureMethod != "RSA-SHA1")
    throw new Error("Un-supported signature method: " + signatureMethod )
  this._signatureMethod= signatureMethod;
  this._nonceSize= nonceSize || 32;
  this._headers= customHeaders || {"Accept" : "*/*",
                                   "Connection" : "close",
                                   "User-Agent" : "Node authentication"}
  this._clientOptions= this._defaultClientOptions= {"requestTokenHttpMethod": "POST",
                                                    "accessTokenHttpMethod": "POST",
                                                    "followRedirects": true};
  this._oauthParameterSeperator = ",";
}
```
- example usage
```shell
...
## OAuth1.0

'''javascript
describe('OAuth1.0',function(){
var OAuth = require('oauth');

it('tests trends Twitter API v1.1',function(done){
  var oauth = new OAuth.OAuth(
    'https://api.twitter.com/oauth/request_token',
    'https://api.twitter.com/oauth/access_token',
    'your application consumer key',
    'your application secret',
    '1.0A',
    null,
    'HMAC-SHA1'
...
```



# <a name="apidoc.module.oauth.OAuth.prototype"></a>[module oauth.OAuth.prototype](#apidoc.module.oauth.OAuth.prototype)

#### <a name="apidoc.element.oauth.OAuth.prototype._buildAuthorizationHeaders"></a>[function <span class="apidocSignatureSpan">oauth.OAuth.prototype.</span>_buildAuthorizationHeaders (orderedParameters)](#apidoc.element.oauth.OAuth.prototype._buildAuthorizationHeaders)
- description and source-code
```javascript
_buildAuthorizationHeaders = function (orderedParameters) {
  var authHeader="OAuth ";
  if( this._isEcho ) {
    authHeader += 'realm="' + this._realm + '",';
  }

  for( var i= 0 ; i < orderedParameters.length; i++) {
     // Whilst the all the parameters should be included within the signature, only the oauth_ arguments
     // should appear within the authorization header.
     if( this._isParameterNameAnOAuthParameter(orderedParameters[i][0]) ) {
      authHeader+= "" + this._encodeData(orderedParameters[i][0])+"=\""+ this._encodeData(orderedParameters[i][1])+"\""+ this._oauthParameterSeperator
;
     }
  }

  authHeader= authHeader.substring(0, authHeader.length-this._oauthParameterSeperator.length);
  return authHeader;
}
```
- example usage
```shell
...
  post_content_type= "application/x-www-form-urlencoded";
}
var parsedUrl= URL.parse( url, false );
if( parsedUrl.protocol == "http:" && !parsedUrl.port ) parsedUrl.port= 80;
if( parsedUrl.protocol == "https:" && !parsedUrl.port ) parsedUrl.port= 443;

var headers= {};
var authorization = this._buildAuthorizationHeaders(orderedParameters);
if ( this._isEcho ) {
  headers["X-Verify-Credentials-Authorization"]= authorization;
}
else {
  headers["Authorization"]= authorization;
}
...
```

#### <a name="apidoc.element.oauth.OAuth.prototype._createClient"></a>[function <span class="apidocSignatureSpan">oauth.OAuth.prototype.</span>_createClient ( port, hostname, method, path, headers, sslEnabled )](#apidoc.element.oauth.OAuth.prototype._createClient)
- description and source-code
```javascript
_createClient = function ( port, hostname, method, path, headers, sslEnabled ) {
  var options = {
    host: hostname,
    port: port,
    path: path,
    method: method,
    headers: headers
  };
  var httpModel;
  if( sslEnabled ) {
    httpModel= https;
  } else {
    httpModel= http;
  }
  return httpModel.request(options);
}
```
- example usage
```shell
...
var path;
if( !parsedUrl.pathname  || parsedUrl.pathname == "" ) parsedUrl.pathname ="/";
if( parsedUrl.query ) path= parsedUrl.pathname + "?"+ parsedUrl.query ;
else path= parsedUrl.pathname;

var request;
if( parsedUrl.protocol == "https:" ) {
  request= this._createClient(parsedUrl.port, parsedUrl.hostname, method, path, headers, true);
}
else {
  request= this._createClient(parsedUrl.port, parsedUrl.hostname, method, path, headers);
}

var clientOptions = this._clientOptions;
if( callback ) {
...
```

#### <a name="apidoc.element.oauth.OAuth.prototype._createSignature"></a>[function <span class="apidocSignatureSpan">oauth.OAuth.prototype.</span>_createSignature (signatureBase, tokenSecret)](#apidoc.element.oauth.OAuth.prototype._createSignature)
- description and source-code
```javascript
_createSignature = function (signatureBase, tokenSecret) {
   if( tokenSecret === undefined ) var tokenSecret= "";
   else tokenSecret= this._encodeData( tokenSecret );
   // consumerSecret is already encoded
   var key= this._consumerSecret + "&" + tokenSecret;

   var hash= ""
   if( this._signatureMethod == "PLAINTEXT" ) {
     hash= key;
   }
   else if (this._signatureMethod == "RSA-SHA1") {
     key = this._privateKey || "";
     hash= crypto.createSign("RSA-SHA1").update(signatureBase).sign(key, 'base64');
   }
   else {
       if( crypto.Hmac ) {
         hash = crypto.createHmac("sha1", key).update(signatureBase).digest("base64");
       }
       else {
         hash= sha1.HMACSHA1(key, signatureBase);
       }
   }
   return hash;
}
```
- example usage
```shell
...
  toDecode = toDecode.replace(/\+/g, " ");
}
return decodeURIComponent( toDecode);
}

exports.OAuth.prototype._getSignature= function(method, url, parameters, tokenSecret) {
var signatureBase= this._createSignatureBase(method, url, parameters);
return this._createSignature( signatureBase, tokenSecret );
}

exports.OAuth.prototype._normalizeUrl= function(url) {
var parsedUrl= URL.parse(url, true)
 var port ="";
 if( parsedUrl.port ) {
   if( (parsedUrl.protocol == "http:" && parsedUrl.port != "80" ) ||
...
```

#### <a name="apidoc.element.oauth.OAuth.prototype._createSignatureBase"></a>[function <span class="apidocSignatureSpan">oauth.OAuth.prototype.</span>_createSignatureBase (method, url, parameters)](#apidoc.element.oauth.OAuth.prototype._createSignatureBase)
- description and source-code
```javascript
_createSignatureBase = function (method, url, parameters) {
  url= this._encodeData( this._normalizeUrl(url) );
  parameters= this._encodeData( parameters );
  return method.toUpperCase() + "&" + url + "&" + parameters;
}
```
- example usage
```shell
...
if( toDecode != null ) {
  toDecode = toDecode.replace(/\+/g, " ");
}
return decodeURIComponent( toDecode);
}

exports.OAuth.prototype._getSignature= function(method, url, parameters, tokenSecret) {
var signatureBase= this._createSignatureBase(method, url, parameters);
return this._createSignature( signatureBase, tokenSecret );
}

exports.OAuth.prototype._normalizeUrl= function(url) {
var parsedUrl= URL.parse(url, true)
 var port ="";
 if( parsedUrl.port ) {
...
```

#### <a name="apidoc.element.oauth.OAuth.prototype._decodeData"></a>[function <span class="apidocSignatureSpan">oauth.OAuth.prototype.</span>_decodeData (toDecode)](#apidoc.element.oauth.OAuth.prototype._decodeData)
- description and source-code
```javascript
_decodeData = function (toDecode) {
  if( toDecode != null ) {
    toDecode = toDecode.replace(/\+/g, " ");
  }
  return decodeURIComponent( toDecode);
}
```
- example usage
```shell
n/a
```

#### <a name="apidoc.element.oauth.OAuth.prototype._encodeData"></a>[function <span class="apidocSignatureSpan">oauth.OAuth.prototype.</span>_encodeData (toEncode)](#apidoc.element.oauth.OAuth.prototype._encodeData)
- description and source-code
```javascript
_encodeData = function (toEncode){
 if( toEncode == null || toEncode == "" ) return ""
 else {
    var result= encodeURIComponent(toEncode);
    // Fix the mismatch between OAuth's  RFC3986's and Javascript's beliefs in what is right and wrong ;)
    return result.replace(/\!/g, "%21")
                 .replace(/\'/g, "%27")
                 .replace(/\(/g, "%28")
                 .replace(/\)/g, "%29")
                 .replace(/\*/g, "%2A");
 }
}
```
- example usage
```shell
...
- OAuth2:   No longer sends the type=webserver argument with the OAuth2 requests (thank you bendiy)
- OAuth2:   Provides a default (and overrideable) User-Agent header (thanks to Andrew Martens & Daniel Mahlow)
- OAuth1:   New followRedirects client option (true by default) (thanks to Pieter Joost van de Sande)
- OAuth1:   Adds RSA-SHA1 support (thanks to Jeffrey D. Van Alstine  & Michael Garvin &  Andreas Knecht)
* 0.9.10
- OAuth2:   Addresses 2 issues that came in with 0.9.9, #129 & #125 (thank you José F. Romaniello)
* 0.9.9
- OAuth1:   Fix the mismatch between the output of querystring.stringify() and this._encodeData(). (thank you rolandboon)
- OAuth2:   Adds Authorization Header and supports extra headers by default ( thanks to Brian Park)
* 0.9.8
- OAuth1:   Support overly-strict OAuth server's that require whitespace separating the Authorization Header parameters  (e.g. 500px
.com) (Thanks to Christian Schwarz)
- OAuth1:   Fix incorrect double-encoding of PLAINTEXT OAuth connections (Thanks to Joe Rozner)
- OAuth1:   Minor safety check added when checking hostnames. (Thanks to Garrick Cheung)
* 0.9.7
- OAuth2:   Pass back any extra response data for calls to getOAuthAccessToken (Thanks to Tang Bo Hao)
...
```

#### <a name="apidoc.element.oauth.OAuth.prototype._getNonce"></a>[function <span class="apidocSignatureSpan">oauth.OAuth.prototype.</span>_getNonce (nonceSize)](#apidoc.element.oauth.OAuth.prototype._getNonce)
- description and source-code
```javascript
_getNonce = function (nonceSize) {
   var result = [];
   var chars= this.NONCE_CHARS;
   var char_pos;
   var nonce_chars_length= chars.length;

   for (var i = 0; i < nonceSize; i++) {
       char_pos= Math.floor(Math.random() * nonce_chars_length);
       result[i]=  chars[char_pos];
   }
   return result.join('');
}
```
- example usage
```shell
...
}
return httpModel.request(options);
}

exports.OAuth.prototype._prepareParameters= function( oauth_token, oauth_token_secret, method, url, extra_params ) {
var oauthParameters= {
    "oauth_timestamp":        this._getTimestamp(),
    "oauth_nonce":            this._getNonce(this._nonceSize),
    "oauth_version":          this._version,
    "oauth_signature_method": this._signatureMethod,
    "oauth_consumer_key":     this._consumerKey
};

if( oauth_token ) {
  oauthParameters["oauth_token"]= oauth_token;
...
```

#### <a name="apidoc.element.oauth.OAuth.prototype._getSignature"></a>[function <span class="apidocSignatureSpan">oauth.OAuth.prototype.</span>_getSignature (method, url, parameters, tokenSecret)](#apidoc.element.oauth.OAuth.prototype._getSignature)
- description and source-code
```javascript
_getSignature = function (method, url, parameters, tokenSecret) {
  var signatureBase= this._createSignatureBase(method, url, parameters);
  return this._createSignature( signatureBase, tokenSecret );
}
```
- example usage
```shell
...

if( oauth_token ) {
  oauthParameters["oauth_token"]= oauth_token;
}

var sig;
if( this._isEcho ) {
  sig = this._getSignature( "GET",  this._verifyCredentials,  this._normaliseRequestParams(oauthParameters), oauth_token_secret);
}
else {
  if( extra_params ) {
    for( var key in extra_params ) {
      if (extra_params.hasOwnProperty(key)) oauthParameters[key]= extra_params[key];
    }
  }
...
```

#### <a name="apidoc.element.oauth.OAuth.prototype._getTimestamp"></a>[function <span class="apidocSignatureSpan">oauth.OAuth.prototype.</span>_getTimestamp ()](#apidoc.element.oauth.OAuth.prototype._getTimestamp)
- description and source-code
```javascript
_getTimestamp = function () {
  return Math.floor( (new Date()).getTime() / 1000 );
}
```
- example usage
```shell
...
  httpModel= http;
}
return httpModel.request(options);
}

exports.OAuth.prototype._prepareParameters= function( oauth_token, oauth_token_secret, method, url, extra_params ) {
var oauthParameters= {
    "oauth_timestamp":        this._getTimestamp(),
    "oauth_nonce":            this._getNonce(this._nonceSize),
    "oauth_version":          this._version,
    "oauth_signature_method": this._signatureMethod,
    "oauth_consumer_key":     this._consumerKey
};

if( oauth_token ) {
...
```

#### <a name="apidoc.element.oauth.OAuth.prototype._isParameterNameAnOAuthParameter"></a>[function <span class="apidocSignatureSpan">oauth.OAuth.prototype.</span>_isParameterNameAnOAuthParameter (parameter)](#apidoc.element.oauth.OAuth.prototype._isParameterNameAnOAuthParameter)
- description and source-code
```javascript
_isParameterNameAnOAuthParameter = function (parameter) {
  var m = parameter.match('^oauth_');
  if( m && ( m[0] === "oauth_" ) ) {
    return true;
  }
  else {
    return false;
  }
}
```
- example usage
```shell
...
  if( this._isEcho ) {
    authHeader += 'realm="' + this._realm + '",';
  }

  for( var i= 0 ; i < orderedParameters.length; i++) {
     // Whilst the all the parameters should be included within the signature, only the oauth_ arguments
     // should appear within the authorization header.
     if( this._isParameterNameAnOAuthParameter(orderedParameters[i][0]) ) {
      authHeader+= "" + this._encodeData(orderedParameters[i][0])+"=\""+ this._encodeData(orderedParameters[i][1])+"\""+ this._oauthParameterSeperator
;
     }
  }

  authHeader= authHeader.substring(0, authHeader.length-this._oauthParameterSeperator.length);
  return authHeader;
}
...
```

#### <a name="apidoc.element.oauth.OAuth.prototype._makeArrayOfArgumentsHash"></a>[function <span class="apidocSignatureSpan">oauth.OAuth.prototype.</span>_makeArrayOfArgumentsHash (argumentsHash)](#apidoc.element.oauth.OAuth.prototype._makeArrayOfArgumentsHash)
- description and source-code
```javascript
_makeArrayOfArgumentsHash = function (argumentsHash) {
  var argument_pairs= [];
  for(var key in argumentsHash ) {
    if (argumentsHash.hasOwnProperty(key)) {
       var value= argumentsHash[key];
       if( Array.isArray(value) ) {
         for(var i=0;i<value.length;i++) {
           argument_pairs[argument_pairs.length]= [key, value[i]];
         }
       }
       else {
         argument_pairs[argument_pairs.length]= [key, value];
       }
    }
  }
  return argument_pairs;
}
```
- example usage
```shell
...
    else return a[0] < b[0] ? -1 : 1;
});

return argument_pairs;
}

exports.OAuth.prototype._normaliseRequestParams= function(args) {
var argument_pairs= this._makeArrayOfArgumentsHash(args);
// First encode them #3.4.1.3.2 .1
for(var i=0;i<argument_pairs.length;i++) {
  argument_pairs[i][0]= this._encodeData( argument_pairs[i][0] );
  argument_pairs[i][1]= this._encodeData( argument_pairs[i][1] );
}

// Then sort them #3.4.1.3.2 .2
...
```

#### <a name="apidoc.element.oauth.OAuth.prototype._normaliseRequestParams"></a>[function <span class="apidocSignatureSpan">oauth.OAuth.prototype.</span>_normaliseRequestParams (args)](#apidoc.element.oauth.OAuth.prototype._normaliseRequestParams)
- description and source-code
```javascript
_normaliseRequestParams = function (args) {
  var argument_pairs= this._makeArrayOfArgumentsHash(args);
  // First encode them #3.4.1.3.2 .1
  for(var i=0;i<argument_pairs.length;i++) {
    argument_pairs[i][0]= this._encodeData( argument_pairs[i][0] );
    argument_pairs[i][1]= this._encodeData( argument_pairs[i][1] );
  }

  // Then sort them #3.4.1.3.2 .2
  argument_pairs= this._sortRequestParams( argument_pairs );

  // Then concatenate together #3.4.1.3.2 .3 & .4
  var args= "";
  for(var i=0;i<argument_pairs.length;i++) {
      args+= argument_pairs[i][0];
      args+= "="
      args+= argument_pairs[i][1];
      if( i < argument_pairs.length-1 ) args+= "&";
  }
  return args;
}
```
- example usage
```shell
...

if( oauth_token ) {
  oauthParameters["oauth_token"]= oauth_token;
}

var sig;
if( this._isEcho ) {
  sig = this._getSignature( "GET",  this._verifyCredentials,  this._normaliseRequestParams(oauthParameters), oauth_token_secret);
}
else {
  if( extra_params ) {
    for( var key in extra_params ) {
      if (extra_params.hasOwnProperty(key)) oauthParameters[key]= extra_params[key];
    }
  }
...
```

#### <a name="apidoc.element.oauth.OAuth.prototype._normalizeUrl"></a>[function <span class="apidocSignatureSpan">oauth.OAuth.prototype.</span>_normalizeUrl (url)](#apidoc.element.oauth.OAuth.prototype._normalizeUrl)
- description and source-code
```javascript
_normalizeUrl = function (url) {
  var parsedUrl= URL.parse(url, true)
   var port ="";
   if( parsedUrl.port ) {
     if( (parsedUrl.protocol == "http:" && parsedUrl.port != "80" ) ||
         (parsedUrl.protocol == "https:" && parsedUrl.port != "443") ) {
           port= ":" + parsedUrl.port;
         }
   }

  if( !parsedUrl.pathname  || parsedUrl.pathname == "" ) parsedUrl.pathname ="/";

  return parsedUrl.protocol + "//" + parsedUrl.hostname + port + parsedUrl.pathname;
}
```
- example usage
```shell
...
   args+= argument_pairs[i][1];
   if( i < argument_pairs.length-1 ) args+= "&";
  }
  return args;
}

exports.OAuth.prototype._createSignatureBase= function(method, url, parameters) {
  url= this._encodeData( this._normalizeUrl(url) );
  parameters= this._encodeData( parameters );
  return method.toUpperCase() + "&" + url + "&" + parameters;
}

exports.OAuth.prototype._createSignature= function(signatureBase, tokenSecret) {
if( tokenSecret === undefined ) var tokenSecret= "";
else tokenSecret= this._encodeData( tokenSecret );
...
```

#### <a name="apidoc.element.oauth.OAuth.prototype._performSecureRequest"></a>[function <span class="apidocSignatureSpan">oauth.OAuth.prototype.</span>_performSecureRequest ( oauth_token, oauth_token_secret, method, url, extra_params, post_body, post_content_type, callback )](#apidoc.element.oauth.OAuth.prototype._performSecureRequest)
- description and source-code
```javascript
_performSecureRequest = function ( oauth_token, oauth_token_secret, method, url, extra_params, post_body, post_content_type, callback ) {
  var orderedParameters= this._prepareParameters(oauth_token, oauth_token_secret, method, url, extra_params);

  if( !post_content_type ) {
    post_content_type= "application/x-www-form-urlencoded";
  }
  var parsedUrl= URL.parse( url, false );
  if( parsedUrl.protocol == "http:" && !parsedUrl.port ) parsedUrl.port= 80;
  if( parsedUrl.protocol == "https:" && !parsedUrl.port ) parsedUrl.port= 443;

  var headers= {};
  var authorization = this._buildAuthorizationHeaders(orderedParameters);
  if ( this._isEcho ) {
    headers["X-Verify-Credentials-Authorization"]= authorization;
  }
  else {
    headers["Authorization"]= authorization;
  }

  headers["Host"] = parsedUrl.host

  for( var key in this._headers ) {
    if (this._headers.hasOwnProperty(key)) {
      headers[key]= this._headers[key];
    }
  }

  // Filter out any passed extra_params that are really to do with OAuth
  for(var key in extra_params) {
    if( this._isParameterNameAnOAuthParameter( key ) ) {
      delete extra_params[key];
    }
  }

  if( (method == "POST" || method == "PUT")  && ( post_body == null && extra_params != null) ) {
    // Fix the mismatch between the output of querystring.stringify() and this._encodeData()
    post_body= querystring.stringify(extra_params)
                       .replace(/\!/g, "%21")
                       .replace(/\'/g, "%27")
                       .replace(/\(/g, "%28")
                       .replace(/\)/g, "%29")
                       .replace(/\*/g, "%2A");
  }

  if( post_body ) {
      if ( Buffer.isBuffer(post_body) ) {
          headers["Content-length"]= post_body.length;
      } else {
          headers["Content-length"]= Buffer.byteLength(post_body);
      }
  } else {
      headers["Content-length"]= 0;
  }

  headers["Content-Type"]= post_content_type;

  var path;
  if( !parsedUrl.pathname  || parsedUrl.pathname == "" ) parsedUrl.pathname ="/";
  if( parsedUrl.query ) path= parsedUrl.pathname + "?"+ parsedUrl.query ;
  else path= parsedUrl.pathname;

  var request;
  if( parsedUrl.protocol == "https:" ) {
    request= this._createClient(parsedUrl.port, parsedUrl.hostname, method, path, headers, true);
  }
  else {
    request= this._createClient(parsedUrl.port, parsedUrl.hostname, method, path, headers);
  }

  var clientOptions = this._clientOptions;
  if( callback ) {
    var data="";
    var self= this;

    // Some hosts *cough* google appear to close the connection early / send no content-length header
    // allow this behaviour.
    var allowEarlyClose= OAuthUtils.isAnEarlyCloseHost( parsedUrl.hostname );
    var callbackCalled= false;
    var passBackControl = function( response ) {
      if(!callbackCalled) {
        callbackCalled= true;
        if ( response.statusCode >= 200 && response.statusCode <= 299 ) {
          callback(null, data, response);
        } else {
          // Follow 301 or 302 redirects with Location HTTP header
          if((response.statusCode == 301 || response.statusCode == 302) && clientOptions.followRedirects && response.headers &&
response.headers.location) {
            self._performSecureRequest( oauth_token, oauth_token_secret, method, response.headers.location, extra_params, post_body
, post_content_type,  callback);
          }
          else {
            callback({ statusCode: response.statusCode, data: data }, data, response);
          }
        }
      }
    }

    request.on('response', function (response) {
      response.setEncoding('utf8');
      response.on('data', function (chunk) {
        data+=chunk;
      });
      response.on('end', function () {
        passBackControl( response );
      });
      response.on('close', function () {
        if( allowEarlyClose ) {
          passBackControl( response );
        }
      });
    });

    request.on("error", function(err) {
      if(!callbackCalled) {
        callbackCalled= true;
        callback( err )
      }
    });

    if( (method == "POST" || method =="PUT") && post_body ! ...
```
- example usage
```shell
...
  if(!callbackCalled) {
    callbackCalled= true;
    if ( response.statusCode >= 200 && response.statusCode <= 299 ) {
      callback(null, data, response);
    } else {
      // Follow 301 or 302 redirects with Location HTTP header
      if((response.statusCode == 301 || response.statusCode == 302) && clientOptions.followRedirects && response.headers && response
.headers.location) {
        self._performSecureRequest( oauth_token, oauth_token_secret, method, response.headers.location, extra_params, post_body,
post_content_type,  callback);
      }
      else {
        callback({ statusCode: response.statusCode, data: data }, data, response);
      }
    }
  }
}
...
```

#### <a name="apidoc.element.oauth.OAuth.prototype._prepareParameters"></a>[function <span class="apidocSignatureSpan">oauth.OAuth.prototype.</span>_prepareParameters ( oauth_token, oauth_token_secret, method, url, extra_params )](#apidoc.element.oauth.OAuth.prototype._prepareParameters)
- description and source-code
```javascript
_prepareParameters = function ( oauth_token, oauth_token_secret, method, url, extra_params ) {
  var oauthParameters= {
      "oauth_timestamp":        this._getTimestamp(),
      "oauth_nonce":            this._getNonce(this._nonceSize),
      "oauth_version":          this._version,
      "oauth_signature_method": this._signatureMethod,
      "oauth_consumer_key":     this._consumerKey
  };

  if( oauth_token ) {
    oauthParameters["oauth_token"]= oauth_token;
  }

  var sig;
  if( this._isEcho ) {
    sig = this._getSignature( "GET",  this._verifyCredentials,  this._normaliseRequestParams(oauthParameters), oauth_token_secret
);
  }
  else {
    if( extra_params ) {
      for( var key in extra_params ) {
        if (extra_params.hasOwnProperty(key)) oauthParameters[key]= extra_params[key];
      }
    }
    var parsedUrl= URL.parse( url, false );

    if( parsedUrl.query ) {
      var key2;
      var extraParameters= querystring.parse(parsedUrl.query);
      for(var key in extraParameters ) {
        var value= extraParameters[key];
          if( typeof value == "object" ){
            // TODO: This probably should be recursive
            for(key2 in value){
              oauthParameters[key + "[" + key2 + "]"] = value[key2];
            }
          } else {
            oauthParameters[key]= value;
          }
        }
    }

    sig = this._getSignature( method,  url,  this._normaliseRequestParams(oauthParameters), oauth_token_secret);
  }

  var orderedParameters= this._sortRequestParams( this._makeArrayOfArgumentsHash(oauthParameters) );
  orderedParameters[orderedParameters.length]= ["oauth_signature", sig];
  return orderedParameters;
}
```
- example usage
```shell
...

var orderedParameters= this._sortRequestParams( this._makeArrayOfArgumentsHash(oauthParameters) );
orderedParameters[orderedParameters.length]= ["oauth_signature", sig];
return orderedParameters;
}

exports.OAuth.prototype._performSecureRequest= function( oauth_token, oauth_token_secret, method, url, extra_params, post_body,
post_content_type,  callback ) {
var orderedParameters= this._prepareParameters(oauth_token, oauth_token_secret, method, url, extra_params);

if( !post_content_type ) {
  post_content_type= "application/x-www-form-urlencoded";
}
var parsedUrl= URL.parse( url, false );
if( parsedUrl.protocol == "http:" && !parsedUrl.port ) parsedUrl.port= 80;
if( parsedUrl.protocol == "https:" && !parsedUrl.port ) parsedUrl.port= 443;
...
```

#### <a name="apidoc.element.oauth.OAuth.prototype._putOrPost"></a>[function <span class="apidocSignatureSpan">oauth.OAuth.prototype.</span>_putOrPost (method, url, oauth_token, oauth_token_secret, post_body, post_content_type, callback)](#apidoc.element.oauth.OAuth.prototype._putOrPost)
- description and source-code
```javascript
_putOrPost = function (method, url, oauth_token, oauth_token_secret, post_body, post_content_type, callback) {
  var extra_params= null;
  if( typeof post_content_type == "function" ) {
    callback= post_content_type;
    post_content_type= null;
  }
  if ( typeof post_body != "string" && !Buffer.isBuffer(post_body) ) {
    post_content_type= "application/x-www-form-urlencoded"
    extra_params= post_body;
    post_body= null;
  }
  return this._performSecureRequest( oauth_token, oauth_token_secret, method, url, extra_params, post_body, post_content_type, callback
 );
}
```
- example usage
```shell
...
    post_body= null;
  }
  return this._performSecureRequest( oauth_token, oauth_token_secret, method, url, extra_params, post_body, post_content_type, callback
 );
}


exports.OAuth.prototype.put= function(url, oauth_token, oauth_token_secret, post_body, post_content_type, callback) {
  return this._putOrPost("PUT", url, oauth_token, oauth_token_secret, post_body, post_content_type, callback);
}

exports.OAuth.prototype.post= function(url, oauth_token, oauth_token_secret, post_body, post_content_type, callback) {
  return this._putOrPost("POST", url, oauth_token, oauth_token_secret, post_body, post_content_type, callback);
}

/**
...
```

#### <a name="apidoc.element.oauth.OAuth.prototype._sortRequestParams"></a>[function <span class="apidocSignatureSpan">oauth.OAuth.prototype.</span>_sortRequestParams (argument_pairs)](#apidoc.element.oauth.OAuth.prototype._sortRequestParams)
- description and source-code
```javascript
_sortRequestParams = function (argument_pairs) {
  // Sort by name, then value.
  argument_pairs.sort(function(a,b) {
      if ( a[0]== b[0] )  {
        return a[1] < b[1] ? -1 : 1;
      }
      else return a[0] < b[0] ? -1 : 1;
  });

  return argument_pairs;
}
```
- example usage
```shell
...
// First encode them #3.4.1.3.2 .1
for(var i=0;i<argument_pairs.length;i++) {
  argument_pairs[i][0]= this._encodeData( argument_pairs[i][0] );
  argument_pairs[i][1]= this._encodeData( argument_pairs[i][1] );
}

// Then sort them #3.4.1.3.2 .2
argument_pairs= this._sortRequestParams( argument_pairs );

// Then concatenate together #3.4.1.3.2 .3 & .4
var args= "";
for(var i=0;i<argument_pairs.length;i++) {
    args+= argument_pairs[i][0];
    args+= "="
    args+= argument_pairs[i][1];
...
```

#### <a name="apidoc.element.oauth.OAuth.prototype.authHeader"></a>[function <span class="apidocSignatureSpan">oauth.OAuth.prototype.</span>authHeader (url, oauth_token, oauth_token_secret, method)](#apidoc.element.oauth.OAuth.prototype.authHeader)
- description and source-code
```javascript
authHeader = function (url, oauth_token, oauth_token_secret, method) {
  if( method === undefined ) {
    var method= "GET";
  }

  var orderedParameters= this._prepareParameters(oauth_token, oauth_token_secret, method, url, {});
  return this._buildAuthorizationHeaders(orderedParameters);
}
```
- example usage
```shell
n/a
```

#### <a name="apidoc.element.oauth.OAuth.prototype.delete"></a>[function <span class="apidocSignatureSpan">oauth.OAuth.prototype.</span>delete (url, oauth_token, oauth_token_secret, callback)](#apidoc.element.oauth.OAuth.prototype.delete)
- description and source-code
```javascript
delete = function (url, oauth_token, oauth_token_secret, callback) {
  return this._performSecureRequest( oauth_token, oauth_token_secret, "DELETE", url, null, "", null, callback );
}
```
- example usage
```shell
n/a
```

#### <a name="apidoc.element.oauth.OAuth.prototype.get"></a>[function <span class="apidocSignatureSpan">oauth.OAuth.prototype.</span>get (url, oauth_token, oauth_token_secret, callback)](#apidoc.element.oauth.OAuth.prototype.get)
- description and source-code
```javascript
get = function (url, oauth_token, oauth_token_secret, callback) {
  return this._performSecureRequest( oauth_token, oauth_token_secret, "GET", url, null, "", null, callback );
}
```
- example usage
```shell
...
  'https://api.twitter.com/oauth/access_token',
  'your application consumer key',
  'your application secret',
  '1.0A',
  null,
  'HMAC-SHA1'
);
oauth.get(
  'https://api.twitter.com/1.1/trends/place.json?id=23424977',
  'your user token for this app', //test user token
  'your user secret for this app', //test user secret
  function (e, data, res){
    if (e) console.error(e);
    console.log(require('util').inspect(data));
    done();
...
```

#### <a name="apidoc.element.oauth.OAuth.prototype.getOAuthAccessToken"></a>[function <span class="apidocSignatureSpan">oauth.OAuth.prototype.</span>getOAuthAccessToken (oauth_token, oauth_token_secret, oauth_verifier, callback)](#apidoc.element.oauth.OAuth.prototype.getOAuthAccessToken)
- description and source-code
```javascript
getOAuthAccessToken = function (oauth_token, oauth_token_secret, oauth_verifier, callback) {
  var extraParams= {};
  if( typeof oauth_verifier == "function" ) {
    callback= oauth_verifier;
  } else {
    extraParams.oauth_verifier= oauth_verifier;
  }

   this._performSecureRequest( oauth_token, oauth_token_secret, this._clientOptions.accessTokenHttpMethod, this._accessUrl, extraParams
, null, null, function(error, data, response) {
         if( error ) callback(error);
         else {
           var results= querystring.parse( data );
           var oauth_access_token= results["oauth_token"];
           delete results["oauth_token"];
           var oauth_access_token_secret= results["oauth_token_secret"];
           delete results["oauth_token_secret"];
           callback(null, oauth_access_token, oauth_access_token_secret, results );
         }
   })
}
```
- example usage
```shell
...
  var twitterConsumerSecret = 'your secret';
  var oauth2 = new OAuth2(server.config.keys.twitter.consumerKey,
    twitterConsumerSecret,
    'https://api.twitter.com/',
    null,
    'oauth2/token',
    null);
  oauth2.getOAuthAccessToken(
    '',
    {'grant_type':'client_credentials'},
    function (e, access_token, refresh_token, results){
    console.log('bearer: ',access_token);
    done();
  });
});
...
```

#### <a name="apidoc.element.oauth.OAuth.prototype.getOAuthRequestToken"></a>[function <span class="apidocSignatureSpan">oauth.OAuth.prototype.</span>getOAuthRequestToken ( extraParams, callback )](#apidoc.element.oauth.OAuth.prototype.getOAuthRequestToken)
- description and source-code
```javascript
getOAuthRequestToken = function ( extraParams, callback ) {
   if( typeof extraParams == "function" ){
     callback = extraParams;
     extraParams = {};
   }
  // Callbacks are 1.0A related
  if( this._authorize_callback ) {
    extraParams["oauth_callback"]= this._authorize_callback;
  }
  this._performSecureRequest( null, null, this._clientOptions.requestTokenHttpMethod, this._requestUrl, extraParams, null, null,
function(error, data, response) {
    if( error ) callback(error);
    else {
      var results= querystring.parse(data);

      var oauth_token= results["oauth_token"];
      var oauth_token_secret= results["oauth_token_secret"];
      delete results["oauth_token"];
      delete results["oauth_token_secret"];
      callback(null, oauth_token, oauth_token_secret,  results );
    }
  });
}
```
- example usage
```shell
n/a
```

#### <a name="apidoc.element.oauth.OAuth.prototype.getProtectedResource"></a>[function <span class="apidocSignatureSpan">oauth.OAuth.prototype.</span>getProtectedResource (url, method, oauth_token, oauth_token_secret, callback)](#apidoc.element.oauth.OAuth.prototype.getProtectedResource)
- description and source-code
```javascript
getProtectedResource = function (url, method, oauth_token, oauth_token_secret, callback) {
  this._performSecureRequest( oauth_token, oauth_token_secret, method, url, null, "", null, callback );
}
```
- example usage
```shell
n/a
```

#### <a name="apidoc.element.oauth.OAuth.prototype.post"></a>[function <span class="apidocSignatureSpan">oauth.OAuth.prototype.</span>post (url, oauth_token, oauth_token_secret, post_body, post_content_type, callback)](#apidoc.element.oauth.OAuth.prototype.post)
- description and source-code
```javascript
post = function (url, oauth_token, oauth_token_secret, post_body, post_content_type, callback) {
  return this._putOrPost("POST", url, oauth_token, oauth_token_secret, post_body, post_content_type, callback);
}
```
- example usage
```shell
n/a
```

#### <a name="apidoc.element.oauth.OAuth.prototype.put"></a>[function <span class="apidocSignatureSpan">oauth.OAuth.prototype.</span>put (url, oauth_token, oauth_token_secret, post_body, post_content_type, callback)](#apidoc.element.oauth.OAuth.prototype.put)
- description and source-code
```javascript
put = function (url, oauth_token, oauth_token_secret, post_body, post_content_type, callback) {
  return this._putOrPost("PUT", url, oauth_token, oauth_token_secret, post_body, post_content_type, callback);
}
```
- example usage
```shell
n/a
```

#### <a name="apidoc.element.oauth.OAuth.prototype.setClientOptions"></a>[function <span class="apidocSignatureSpan">oauth.OAuth.prototype.</span>setClientOptions (options)](#apidoc.element.oauth.OAuth.prototype.setClientOptions)
- description and source-code
```javascript
setClientOptions = function (options) {
  var key,
      mergedOptions= {},
      hasOwnProperty= Object.prototype.hasOwnProperty;

  for( key in this._defaultClientOptions ) {
    if( !hasOwnProperty.call(options, key) ) {
      mergedOptions[key]= this._defaultClientOptions[key];
    } else {
      mergedOptions[key]= options[key];
    }
  }

  this._clientOptions= mergedOptions;
}
```
- example usage
```shell
n/a
```

#### <a name="apidoc.element.oauth.OAuth.prototype.signUrl"></a>[function <span class="apidocSignatureSpan">oauth.OAuth.prototype.</span>signUrl (url, oauth_token, oauth_token_secret, method)](#apidoc.element.oauth.OAuth.prototype.signUrl)
- description and source-code
```javascript
signUrl = function (url, oauth_token, oauth_token_secret, method) {

  if( method === undefined ) {
    var method= "GET";
  }

  var orderedParameters= this._prepareParameters(oauth_token, oauth_token_secret, method, url, {});
  var parsedUrl= URL.parse( url, false );

  var query="";
  for( var i= 0 ; i < orderedParameters.length; i++) {
    query+= orderedParameters[i][0]+"="+ this._encodeData(orderedParameters[i][1]) + "&";
  }
  query= query.substring(0, query.length-1);

  return parsedUrl.protocol + "//"+ parsedUrl.host + parsedUrl.pathname + "?" + query;
}
```
- example usage
```shell
n/a
```



# <a name="apidoc.module.oauth.OAuth2"></a>[module oauth.OAuth2](#apidoc.module.oauth.OAuth2)

#### <a name="apidoc.element.oauth.OAuth2.OAuth2"></a>[function <span class="apidocSignatureSpan">oauth.</span>OAuth2 (clientId, clientSecret, baseSite, authorizePath, accessTokenPath, customHeaders)](#apidoc.element.oauth.OAuth2.OAuth2)
- description and source-code
```javascript
OAuth2 = function (clientId, clientSecret, baseSite, authorizePath, accessTokenPath, customHeaders) {
  this._clientId= clientId;
  this._clientSecret= clientSecret;
  this._baseSite= baseSite;
  this._authorizeUrl= authorizePath || "/oauth/authorize";
  this._accessTokenUrl= accessTokenPath || "/oauth/access_token";
  this._accessTokenName= "access_token";
  this._authMethod= "Bearer";
  this._customHeaders = customHeaders || {};
  this._useAuthorizationHeaderForGET= false;

  //our agent
  this._agent = undefined;
}
```
- example usage
```shell
n/a
```



# <a name="apidoc.module.oauth.OAuth2.prototype"></a>[module oauth.OAuth2.prototype](#apidoc.module.oauth.OAuth2.prototype)

#### <a name="apidoc.element.oauth.OAuth2.prototype._chooseHttpLibrary"></a>[function <span class="apidocSignatureSpan">oauth.OAuth2.prototype.</span>_chooseHttpLibrary ( parsedUrl )](#apidoc.element.oauth.OAuth2.prototype._chooseHttpLibrary)
- description and source-code
```javascript
_chooseHttpLibrary = function ( parsedUrl ) {
  var http_library= https;
  // As this is OAUth2, we *assume* https unless told explicitly otherwise.
  if( parsedUrl.protocol != "https:" ) {
    http_library= http;
  }
  return http_library;
}
```
- example usage
```shell
...
exports.OAuth2.prototype._request= function(method, url, headers, post_body, access_token, callback) {

var parsedUrl= URL.parse( url, true );
if( parsedUrl.protocol == "https:" && !parsedUrl.port ) {
  parsedUrl.port= 443;
}

var http_library= this._chooseHttpLibrary( parsedUrl );


var realHeaders= {};
for( var key in this._customHeaders ) {
  realHeaders[key]= this._customHeaders[key];
}
if( headers ) {
...
```

#### <a name="apidoc.element.oauth.OAuth2.prototype._executeRequest"></a>[function <span class="apidocSignatureSpan">oauth.OAuth2.prototype.</span>_executeRequest ( http_library, options, post_body, callback )](#apidoc.element.oauth.OAuth2.prototype._executeRequest)
- description and source-code
```javascript
_executeRequest = function ( http_library, options, post_body, callback ) {
  // Some hosts *cough* google appear to close the connection early / send no content-length header
  // allow this behaviour.
  var allowEarlyClose= OAuthUtils.isAnEarlyCloseHost(options.host);
  var callbackCalled= false;
  function passBackControl( response, result ) {
    if(!callbackCalled) {
      callbackCalled=true;
      if( !(response.statusCode >= 200 && response.statusCode <= 299) && (response.statusCode != 301) && (response.statusCode !=
302) ) {
        callback({ statusCode: response.statusCode, data: result });
      } else {
        callback(null, result, response);
      }
    }
  }

  var result= "";

  //set the agent on the request options
  if (this._agent) {
    options.agent = this._agent;
  }

  var request = http_library.request(options);
  request.on('response', function (response) {
    response.on("data", function (chunk) {
      result+= chunk
    });
    response.on("close", function (err) {
      if( allowEarlyClose ) {
        passBackControl( response, result );
      }
    });
    response.addListener("end", function () {
      passBackControl( response, result );
    });
  });
  request.on('error', function(e) {
    callbackCalled= true;
    callback(e);
  });

  if( (options.method == 'POST' || options.method == 'PUT') && post_body ) {
     request.write(post_body);
  }
  request.end();
}
```
- example usage
```shell
...
  host:parsedUrl.hostname,
  port: parsedUrl.port,
  path: parsedUrl.pathname + queryStr,
  method: method,
  headers: realHeaders
};

this._executeRequest( http_library, options, post_body, callback );
}

exports.OAuth2.prototype._executeRequest= function( http_library, options, post_body, callback ) {
// Some hosts *cough* google appear to close the connection early / send no content-length header
// allow this behaviour.
var allowEarlyClose= OAuthUtils.isAnEarlyCloseHost(options.host);
var callbackCalled= false;
...
```

#### <a name="apidoc.element.oauth.OAuth2.prototype._getAccessTokenUrl"></a>[function <span class="apidocSignatureSpan">oauth.OAuth2.prototype.</span>_getAccessTokenUrl ()](#apidoc.element.oauth.OAuth2.prototype._getAccessTokenUrl)
- description and source-code
```javascript
_getAccessTokenUrl = function () {
  return this._baseSite + this._accessTokenUrl;<span class="apidocCodeCommentSpan"> /* + "?" + querystring.stringify(params); */
</span>}
```
- example usage
```shell
...

var post_data= querystring.stringify( params );
var post_headers= {
     'Content-Type': 'application/x-www-form-urlencoded'
 };


this._request("POST", this._getAccessTokenUrl(), post_headers, post_data, null, function(error, data, response) {
  if( error )  callback(error);
  else {
    var results;
    try {
      // As of http://tools.ietf.org/html/draft-ietf-oauth-v2-07
      // responses should be in JSON
      results= JSON.parse( data );
...
```

#### <a name="apidoc.element.oauth.OAuth2.prototype._request"></a>[function <span class="apidocSignatureSpan">oauth.OAuth2.prototype.</span>_request (method, url, headers, post_body, access_token, callback)](#apidoc.element.oauth.OAuth2.prototype._request)
- description and source-code
```javascript
_request = function (method, url, headers, post_body, access_token, callback) {

  var parsedUrl= URL.parse( url, true );
  if( parsedUrl.protocol == "https:" && !parsedUrl.port ) {
    parsedUrl.port= 443;
  }

  var http_library= this._chooseHttpLibrary( parsedUrl );


  var realHeaders= {};
  for( var key in this._customHeaders ) {
    realHeaders[key]= this._customHeaders[key];
  }
  if( headers ) {
    for(var key in headers) {
      realHeaders[key] = headers[key];
    }
  }
  realHeaders['Host']= parsedUrl.host;

  if (!realHeaders['User-Agent']) {
    realHeaders['User-Agent'] = 'Node-oauth';
  }

  if( post_body ) {
      if ( Buffer.isBuffer(post_body) ) {
          realHeaders["Content-Length"]= post_body.length;
      } else {
          realHeaders["Content-Length"]= Buffer.byteLength(post_body);
      }
  } else {
      realHeaders["Content-length"]= 0;
  }

  if( access_token && !('Authorization' in realHeaders)) {
    if( ! parsedUrl.query ) parsedUrl.query= {};
    parsedUrl.query[this._accessTokenName]= access_token;
  }

  var queryStr= querystring.stringify(parsedUrl.query);
  if( queryStr ) queryStr=  "?" + queryStr;
  var options = {
    host:parsedUrl.hostname,
    port: parsedUrl.port,
    path: parsedUrl.pathname + queryStr,
    method: method,
    headers: realHeaders
  };

  this._executeRequest( http_library, options, post_body, callback );
}
```
- example usage
```shell
...

var post_data= querystring.stringify( params );
var post_headers= {
     'Content-Type': 'application/x-www-form-urlencoded'
 };


this._request("POST", this._getAccessTokenUrl(), post_headers, post_data, null, function(error, data, response) {
  if( error )  callback(error);
  else {
    var results;
    try {
      // As of http://tools.ietf.org/html/draft-ietf-oauth-v2-07
      // responses should be in JSON
      results= JSON.parse( data );
...
```

#### <a name="apidoc.element.oauth.OAuth2.prototype.buildAuthHeader"></a>[function <span class="apidocSignatureSpan">oauth.OAuth2.prototype.</span>buildAuthHeader (token)](#apidoc.element.oauth.OAuth2.prototype.buildAuthHeader)
- description and source-code
```javascript
buildAuthHeader = function (token) {
  return this._authMethod + ' ' + token;
}
```
- example usage
```shell
...
// Deprecated
exports.OAuth2.prototype.getProtectedResource= function(url, access_token, callback) {
  this._request("GET", url, {}, "", access_token, callback );
}

exports.OAuth2.prototype.get= function(url, access_token, callback) {
  if( this._useAuthorizationHeaderForGET ) {
    var headers= {'Authorization': this.buildAuthHeader(access_token) }
    access_token= null;
  }
  else {
    headers= {};
  }
  this._request("GET", url, headers, "", access_token, callback );
}
...
```

#### <a name="apidoc.element.oauth.OAuth2.prototype.get"></a>[function <span class="apidocSignatureSpan">oauth.OAuth2.prototype.</span>get (url, access_token, callback)](#apidoc.element.oauth.OAuth2.prototype.get)
- description and source-code
```javascript
get = function (url, access_token, callback) {
  if( this._useAuthorizationHeaderForGET ) {
    var headers= {'Authorization': this.buildAuthHeader(access_token) }
    access_token= null;
  }
  else {
    headers= {};
  }
  this._request("GET", url, headers, "", access_token, callback );
}
```
- example usage
```shell
...
  'https://api.twitter.com/oauth/access_token',
  'your application consumer key',
  'your application secret',
  '1.0A',
  null,
  'HMAC-SHA1'
);
oauth.get(
  'https://api.twitter.com/1.1/trends/place.json?id=23424977',
  'your user token for this app', //test user token
  'your user secret for this app', //test user secret
  function (e, data, res){
    if (e) console.error(e);
    console.log(require('util').inspect(data));
    done();
...
```

#### <a name="apidoc.element.oauth.OAuth2.prototype.getAuthorizeUrl"></a>[function <span class="apidocSignatureSpan">oauth.OAuth2.prototype.</span>getAuthorizeUrl ( params )](#apidoc.element.oauth.OAuth2.prototype.getAuthorizeUrl)
- description and source-code
```javascript
getAuthorizeUrl = function ( params ) {
  var params= params || {};
  params['client_id'] = this._clientId;
  return this._baseSite + this._authorizeUrl + "?" + querystring.stringify(params);
}
```
- example usage
```shell
n/a
```

#### <a name="apidoc.element.oauth.OAuth2.prototype.getOAuthAccessToken"></a>[function <span class="apidocSignatureSpan">oauth.OAuth2.prototype.</span>getOAuthAccessToken (code, params, callback)](#apidoc.element.oauth.OAuth2.prototype.getOAuthAccessToken)
- description and source-code
```javascript
getOAuthAccessToken = function (code, params, callback) {
  var params= params || {};
  params['client_id'] = this._clientId;
  params['client_secret'] = this._clientSecret;
  var codeParam = (params.grant_type === 'refresh_token') ? 'refresh_token' : 'code';
  params[codeParam]= code;

  var post_data= querystring.stringify( params );
  var post_headers= {
       'Content-Type': 'application/x-www-form-urlencoded'
   };


  this._request("POST", this._getAccessTokenUrl(), post_headers, post_data, null, function(error, data, response) {
    if( error )  callback(error);
    else {
      var results;
      try {
        // As of http://tools.ietf.org/html/draft-ietf-oauth-v2-07
        // responses should be in JSON
        results= JSON.parse( data );
      }
      catch(e) {
        // .... However both Facebook + Github currently use rev05 of the spec
        // and neither seem to specify a content-type correctly in their response headers :(
        // clients of these services will suffer a *minor* performance cost of the exception
        // being thrown
        results= querystring.parse( data );
      }
      var access_token= results["access_token"];
      var refresh_token= results["refresh_token"];
      delete results["refresh_token"];
      callback(null, access_token, refresh_token, results); // callback results =-=
    }
  });
}
```
- example usage
```shell
...
  var twitterConsumerSecret = 'your secret';
  var oauth2 = new OAuth2(server.config.keys.twitter.consumerKey,
    twitterConsumerSecret,
    'https://api.twitter.com/',
    null,
    'oauth2/token',
    null);
  oauth2.getOAuthAccessToken(
    '',
    {'grant_type':'client_credentials'},
    function (e, access_token, refresh_token, results){
    console.log('bearer: ',access_token);
    done();
  });
});
...
```

#### <a name="apidoc.element.oauth.OAuth2.prototype.getProtectedResource"></a>[function <span class="apidocSignatureSpan">oauth.OAuth2.prototype.</span>getProtectedResource (url, access_token, callback)](#apidoc.element.oauth.OAuth2.prototype.getProtectedResource)
- description and source-code
```javascript
getProtectedResource = function (url, access_token, callback) {
  this._request("GET", url, {}, "", access_token, callback );
}
```
- example usage
```shell
n/a
```

#### <a name="apidoc.element.oauth.OAuth2.prototype.setAccessTokenName"></a>[function <span class="apidocSignatureSpan">oauth.OAuth2.prototype.</span>setAccessTokenName ( name )](#apidoc.element.oauth.OAuth2.prototype.setAccessTokenName)
- description and source-code
```javascript
setAccessTokenName = function ( name ) {
  this._accessTokenName= name;
}
```
- example usage
```shell
n/a
```

#### <a name="apidoc.element.oauth.OAuth2.prototype.setAgent"></a>[function <span class="apidocSignatureSpan">oauth.OAuth2.prototype.</span>setAgent (agent)](#apidoc.element.oauth.OAuth2.prototype.setAgent)
- description and source-code
```javascript
setAgent = function (agent) {
  this._agent = agent;
}
```
- example usage
```shell
n/a
```

#### <a name="apidoc.element.oauth.OAuth2.prototype.setAuthMethod"></a>[function <span class="apidocSignatureSpan">oauth.OAuth2.prototype.</span>setAuthMethod ( authMethod )](#apidoc.element.oauth.OAuth2.prototype.setAuthMethod)
- description and source-code
```javascript
setAuthMethod = function ( authMethod ) {
  this._authMethod = authMethod;
}
```
- example usage
```shell
n/a
```

#### <a name="apidoc.element.oauth.OAuth2.prototype.useAuthorizationHeaderforGET"></a>[function <span class="apidocSignatureSpan">oauth.OAuth2.prototype.</span>useAuthorizationHeaderforGET (useIt)](#apidoc.element.oauth.OAuth2.prototype.useAuthorizationHeaderforGET)
- description and source-code
```javascript
useAuthorizationHeaderforGET = function (useIt) {
  this._useAuthorizationHeaderForGET= useIt;
}
```
- example usage
```shell
n/a
```



# <a name="apidoc.module.oauth.OAuthEcho"></a>[module oauth.OAuthEcho](#apidoc.module.oauth.OAuthEcho)

#### <a name="apidoc.element.oauth.OAuthEcho.OAuthEcho"></a>[function <span class="apidocSignatureSpan">oauth.</span>OAuthEcho (realm, verify_credentials, consumerKey, consumerSecret, version, signatureMethod, nonceSize, customHeaders)](#apidoc.element.oauth.OAuthEcho.OAuthEcho)
- description and source-code
```javascript
OAuthEcho = function (realm, verify_credentials, consumerKey, consumerSecret, version, signatureMethod, nonceSize, customHeaders) {
  this._isEcho = true;

  this._realm= realm;
  this._verifyCredentials = verify_credentials;
  this._consumerKey= consumerKey;
  this._consumerSecret= this._encodeData( consumerSecret );
  if (signatureMethod == "RSA-SHA1") {
    this._privateKey = consumerSecret;
  }
  this._version= version;

  if( signatureMethod != "PLAINTEXT" && signatureMethod != "HMAC-SHA1" && signatureMethod != "RSA-SHA1")
    throw new Error("Un-supported signature method: " + signatureMethod );
  this._signatureMethod= signatureMethod;
  this._nonceSize= nonceSize || 32;
  this._headers= customHeaders || {"Accept" : "*/*",
                                   "Connection" : "close",
                                   "User-Agent" : "Node authentication"};
  this._oauthParameterSeperator = ",";
}
```
- example usage
```shell
n/a
```



# <a name="apidoc.module.oauth._utils"></a>[module oauth._utils](#apidoc.module.oauth._utils)

#### <a name="apidoc.element.oauth._utils.isAnEarlyCloseHost"></a>[function <span class="apidocSignatureSpan">oauth._utils.</span>isAnEarlyCloseHost ( hostName )](#apidoc.element.oauth._utils.isAnEarlyCloseHost)
- description and source-code
```javascript
isAnEarlyCloseHost = function ( hostName ) {
  return hostName && hostName.match(".*google(apis)?.com$")
}
```
- example usage
```shell
...
  var clientOptions = this._clientOptions;
  if( callback ) {
var data="";
var self= this;

// Some hosts *cough* google appear to close the connection early / send no content-length header
// allow this behaviour.
var allowEarlyClose= OAuthUtils.isAnEarlyCloseHost( parsedUrl.hostname );
var callbackCalled= false;
var passBackControl = function( response ) {
  if(!callbackCalled) {
    callbackCalled= true;
    if ( response.statusCode >= 200 && response.statusCode <= 299 ) {
      callback(null, data, response);
    } else {
...
```



# <a name="apidoc.module.oauth.oauth"></a>[module oauth.oauth](#apidoc.module.oauth.oauth)

#### <a name="apidoc.element.oauth.oauth.OAuth"></a>[function <span class="apidocSignatureSpan">oauth.oauth.</span>OAuth (requestUrl, accessUrl, consumerKey, consumerSecret, version, authorize_callback, signatureMethod, nonceSize, customHeaders )](#apidoc.element.oauth.oauth.OAuth)
- description and source-code
```javascript
OAuth = function (requestUrl, accessUrl, consumerKey, consumerSecret, version, authorize_callback, signatureMethod, nonceSize, customHeaders ) {
  this._isEcho = false;

  this._requestUrl= requestUrl;
  this._accessUrl= accessUrl;
  this._consumerKey= consumerKey;
  this._consumerSecret= this._encodeData( consumerSecret );
  if (signatureMethod == "RSA-SHA1") {
    this._privateKey = consumerSecret;
  }
  this._version= version;
  if( authorize_callback === undefined ) {
    this._authorize_callback= "oob";
  }
  else {
    this._authorize_callback= authorize_callback;
  }

  if( signatureMethod != "PLAINTEXT" && signatureMethod != "HMAC-SHA1" && signatureMethod != "RSA-SHA1")
    throw new Error("Un-supported signature method: " + signatureMethod )
  this._signatureMethod= signatureMethod;
  this._nonceSize= nonceSize || 32;
  this._headers= customHeaders || {"Accept" : "*/*",
                                   "Connection" : "close",
                                   "User-Agent" : "Node authentication"}
  this._clientOptions= this._defaultClientOptions= {"requestTokenHttpMethod": "POST",
                                                    "accessTokenHttpMethod": "POST",
                                                    "followRedirects": true};
  this._oauthParameterSeperator = ",";
}
```
- example usage
```shell
...
## OAuth1.0

'''javascript
describe('OAuth1.0',function(){
var OAuth = require('oauth');

it('tests trends Twitter API v1.1',function(done){
  var oauth = new OAuth.OAuth(
    'https://api.twitter.com/oauth/request_token',
    'https://api.twitter.com/oauth/access_token',
    'your application consumer key',
    'your application secret',
    '1.0A',
    null,
    'HMAC-SHA1'
...
```

#### <a name="apidoc.element.oauth.oauth.OAuthEcho"></a>[function <span class="apidocSignatureSpan">oauth.oauth.</span>OAuthEcho (realm, verify_credentials, consumerKey, consumerSecret, version, signatureMethod, nonceSize, customHeaders)](#apidoc.element.oauth.oauth.OAuthEcho)
- description and source-code
```javascript
OAuthEcho = function (realm, verify_credentials, consumerKey, consumerSecret, version, signatureMethod, nonceSize, customHeaders) {
  this._isEcho = true;

  this._realm= realm;
  this._verifyCredentials = verify_credentials;
  this._consumerKey= consumerKey;
  this._consumerSecret= this._encodeData( consumerSecret );
  if (signatureMethod == "RSA-SHA1") {
    this._privateKey = consumerSecret;
  }
  this._version= version;

  if( signatureMethod != "PLAINTEXT" && signatureMethod != "HMAC-SHA1" && signatureMethod != "RSA-SHA1")
    throw new Error("Un-supported signature method: " + signatureMethod );
  this._signatureMethod= signatureMethod;
  this._nonceSize= nonceSize || 32;
  this._headers= customHeaders || {"Accept" : "*/*",
                                   "Connection" : "close",
                                   "User-Agent" : "Node authentication"};
  this._oauthParameterSeperator = ",";
}
```
- example usage
```shell
n/a
```



# <a name="apidoc.module.oauth.oauth2"></a>[module oauth.oauth2](#apidoc.module.oauth.oauth2)

#### <a name="apidoc.element.oauth.oauth2.OAuth2"></a>[function <span class="apidocSignatureSpan">oauth.oauth2.</span>OAuth2 (clientId, clientSecret, baseSite, authorizePath, accessTokenPath, customHeaders)](#apidoc.element.oauth.oauth2.OAuth2)
- description and source-code
```javascript
OAuth2 = function (clientId, clientSecret, baseSite, authorizePath, accessTokenPath, customHeaders) {
  this._clientId= clientId;
  this._clientSecret= clientSecret;
  this._baseSite= baseSite;
  this._authorizeUrl= authorizePath || "/oauth/authorize";
  this._accessTokenUrl= accessTokenPath || "/oauth/access_token";
  this._accessTokenName= "access_token";
  this._authMethod= "Bearer";
  this._customHeaders = customHeaders || {};
  this._useAuthorizationHeaderForGET= false;

  //our agent
  this._agent = undefined;
}
```
- example usage
```shell
n/a
```



# <a name="apidoc.module.oauth.sha1"></a>[module oauth.sha1](#apidoc.module.oauth.sha1)

#### <a name="apidoc.element.oauth.sha1.HMACSHA1"></a>[function <span class="apidocSignatureSpan">oauth.sha1.</span>HMACSHA1 (key, data)](#apidoc.element.oauth.sha1.HMACSHA1)
- description and source-code
```javascript
HMACSHA1 = function (key, data) {
  return b64_hmac_sha1(key, data);
}
```
- example usage
```shell
...
     hash= crypto.createSign("RSA-SHA1").update(signatureBase).sign(key, 'base64');
   }
   else {
       if( crypto.Hmac ) {
         hash = crypto.createHmac("sha1", key).update(signatureBase).digest("base64");
       }
       else {
         hash= sha1.HMACSHA1(key, signatureBase);
       }
   }
   return hash;
}
exports.OAuth.prototype.NONCE_CHARS= ['a','b','c','d','e','f','g','h','i','j','k','l','m','n',
'o','p','q','r','s','t','u','v','w','x','y','z','A','B',
'C','D','E','F','G','H','I','J','K','L','M','N','O','P',
...
```



# misc
- this document was created with [utility2](https://github.com/kaizhu256/node-utility2)
