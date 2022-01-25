### Computer Networks
#### <u> Proxy Server Assignment </u>

This assignment aims to build a local proxy server in python on a specific port. All the request from specified ports to internet will go through this proxy server and the response will be redirect from this server only.

### <u> Features </u>

#### 1. <u>Requests:</u>
- The server can handle basic http requests. Once the requests is made to this proxy server, it determines the desitation IP address and sends the request to that address, once a response is received from that host, the response is again returned back to the client.

#### 2. <u>Blacklists:</u>

- We have stored the list of blacklisted IP addresses as CIDR format in a file named `blacklist.txt`. The proxy server resolves the list of balcklisted IPs from this file, and then whenever a request is made , the proxy checks if the destination IP is in the blacklist, if the destination is in blaklist, then error response is returned. Otherwise normal response is returned.

#### 3. <u>Credentials:</u>

- There is list of valid Credentials stored on the proxy server, if the user sends credentials with requrest , the proxy server checks whether the credentials are valid, if they are user is allowed to access IPs in blacklist.

#### 4. <u>Caching:</u>
- We add each request to a list and dictionary on the proxy server with time stamp. Each time a request is made we increament the count in the dictionary for that url key. If there are more than 3 requests within 5 mins, and again a request is made on that url, we make a request with "If modified since" flag, if the site hasn't modified we return the chached response if not we make again the request and send the new response.
