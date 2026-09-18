// VARVEL - STATIC LAB-ONLY DoH certificate for the governed channel's DNS-over-HTTPS arm.
//
// *** LAB USE ONLY - NEVER OPERATOR-GRADE ***
// This is a fixed, self-signed cert (CN=varvel-doh-lab.local, RSA-2048, valid 2026-08-04
// to 2036-08-01) so the DoH transport works out of the box on the sealed practice range
// with a STABLE thumbprint the agent can pin. The private key ships in the repo by
// design: it protects a range wire, not real infrastructure. Real engagements MUST pass
// their own PEM via the channel's doh:{ cert, key } option (operator certs always win -
// see engine/callback.mjs _armDoh; status reports certSource 'provided' vs 'lab').
//
// Generated once with:
//   openssl req -x509 -newkey rsa:2048 -nodes -keyout k.pem -out c.pem -days 3650 \
//     -subj "/CN=varvel-doh-lab.local"
//
// DOH_LAB_THUMBPRINT = SHA256 over the DER cert, uppercase hex, no colons
//   (openssl x509 -in c.pem -noout -fingerprint -sha256)
// The agent pins EXACTLY this value - it never disables TLS validation (see
// agents/varvel-agent.ps1 Set-DohTlsPin).

export const DOH_LAB_CERT = `-----BEGIN CERTIFICATE-----
MIIDHzCCAgegAwIBAgIUE7G32qwdr4WXMH//X4NdH0T0HXQwDQYJKoZIhvcNAQEL
BQAwHzEdMBsGA1UEAwwUdmFydmVsLWRvaC1sYWIubG9jYWwwHhcNMjYwODA0MjMy
MDEzWhcNMzYwODAxMjMyMDEzWjAfMR0wGwYDVQQDDBR2YXJ2ZWwtZG9oLWxhYi5s
b2NhbDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAI7FB3gQjWEnHrQU
Z2uPUur0BTaKwb9xYt+T6t/C4cE0qFE3RGk9gM0yghKU8vh7Ooi6764xJkoYzK73
6w4jxsIb3fMYeJtFBvAPs4yJ9awedek/rlwXGVbpwDoVCQJyygPjEsCBXrNuB58Z
g5B84zAW7qoi0ETLNetcirypayQrOoiIOHyztcLqVvF9WqSrQgl4jw9ZNErGJ/ik
33cK61j2gwAFN7LaYKgP/6cS7OftI4YdNem3se1qIll7tNPkuMZ/XZgSS6EyGxUe
02DkhjmR24WOCI+ZYYDlrhAC+46tQ9XDWKYFzxNWE4OqocPlxmPQOxBROPNV07y0
G85YgmcCAwEAAaNTMFEwHQYDVR0OBBYEFLcDfVdx4tZ8URPOBYjPS1zC0jmbMB8G
A1UdIwQYMBaAFLcDfVdx4tZ8URPOBYjPS1zC0jmbMA8GA1UdEwEB/wQFMAMBAf8w
DQYJKoZIhvcNAQELBQADggEBAIvTM9/e1g88asWAzBK/lbirDU2UetHK8dtpb5kG
xcstnlNdllJd8TJ9jt22f/d8vMWiHiVWUUCIESVaVWxXrTLHQMeqFP0KVqSPbqcO
AB06Urxt0+3NhjqIS3ByVlY3MjK8JuEoshalGKX+6f4KzLhH34y0DI+DlnWwTtz0
Ao29OHhIvS80QFrA3sY+kxkb5pHCMa1mxv4/PCh5Cy/BkrOeoUiHG0QWzx8CWZv1
gu3f1/mbF31vzmQhBc7b07L4BdekOiu9yeVdfdOnkJHHOjps9nNb6HlYhJV7nlCh
wmOtxLNM9tp1s9TjQeZNINpW8JScr+b4jfBEzr+xYnEK7MM=
-----END CERTIFICATE-----`;

export const DOH_LAB_KEY = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCOxQd4EI1hJx60
FGdrj1Lq9AU2isG/cWLfk+rfwuHBNKhRN0RpPYDNMoISlPL4ezqIuu+uMSZKGMyu
9+sOI8bCG93zGHibRQbwD7OMifWsHnXpP65cFxlW6cA6FQkCcsoD4xLAgV6zbgef
GYOQfOMwFu6qItBEyzXrXIq8qWskKzqIiDh8s7XC6lbxfVqkq0IJeI8PWTRKxif4
pN93CutY9oMABTey2mCoD/+nEuzn7SOGHTXpt7HtaiJZe7TT5LjGf12YEkuhMhsV
HtNg5IY5kduFjgiPmWGA5a4QAvuOrUPVw1imBc8TVhODqqHD5cZj0DsQUTjzVdO8
tBvOWIJnAgMBAAECggEAEoM17rmmu3xJHOywZGAXTmQJ8QKZEOvw+DDD+fPZNiZP
1QgnlMXm17S+7Q3nW5UPB//FaH7zChShJeb70b+N3EmkxAreSLPwrFw82fJhqsng
XDhnsYVFQeHZjS6BFpIv48Uj/1ZHI1kXH+g9CRVImEnA9MrC2sjG2xgK3V/ShsPq
lsN3cGxTpRPJ9cZB4IShafoqjHwJfTYkkoN3f5+DQ8LxQhTylb0lCjW6k3CkJJKL
3GnD0u/tyNPAYhsMdZBux26uTJHEDtv4gCu5po7HZwcaErmthD72oSXRJLj5cDfx
H4zfRKUXycxDHgofFvJk7lv7GIJN/0vxXh5wgb59AQKBgQDIWHGqiUagR3f+vnAL
XFhjZfcGDByKoLqabVP+HJbuSbpKuuRuymJc97Bww85hlTCJL0FlGIt3mvRjzR2Q
5i2Tophx6KlCXf5yN/TAmnyuXxX/WCw5giYRduR7k8WqQwZZpHzRLPHXUnhKF/Sl
5LWBW9gcXCHSC3bcqOreh+D+JwKBgQC2bhVIfI+a1Q3/dxEtGQM40Fggwu7hqJw3
6PFDll7vSMRpw6VQRJkwO5YuRcyZoEHNKTNpSY8D5OFQPF+hKzQIKhBR832AiaHv
eNeY4b73EYliDoq1/bX7gXdHA53VFd4u89I5GlreTSAndglVysePS8hbyDS/ubi/
OWM32OdBwQKBgQCqfnncww4TgD6hz7bSNDgT/sYFo3D2mGm02a1M50+aYavjxMB5
eEnVDARfMoMDkE7JsClau1SU6I1qEThEA15t8UUCSxkfnZXX5b6n2dCZI9o4fvTD
y/pRinhOoibpCjjxOIXwDOuSbmBnzZMpSkUcXOjA2bb+ZTs19ZpK3h+eqQKBgBK0
AIyY8KQgGbpKO8GS4eiuO4rIUXNjNPjqcenK/dqsbC6nt0gecFIomcIOt+Y8LuLY
yYOO3hG5Inx2ZBuC8Wew4FF2lDRcZ/TEP95Vrp1n99zMvt3fsAuj/1WRgln5Tvkj
WDcwg4ZtA9Hn4RchngoL6/O09+t8H/vC53AvVa5BAoGASOYh6U/vkgB41lx2sbV4
yQH+12EndmU6DRzoi02NAXcFbHApyh1wcbg6HODTm9GPAebkS5Y7qz9JIx927qXg
gBUyrf2jYVMVdXD1SyTeSGN27QP6tbFd85lER7BenXj1pIC9MscM4aAqxHmkeRN5
geFx75Jqeqf0YCF9bieKzF8=
-----END PRIVATE KEY-----`;

export const DOH_LAB_THUMBPRINT = '75196C9AC3C596F072C8A22D6F3D76B96DEABF811C731D0ACAC1F3C3876812B1';
