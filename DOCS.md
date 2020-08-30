# Login
```console
curl -X POST "http://fs.panictriggers.xyz/api/login" -H "Content-Type: application/json" -d '{"username": "username", "password": "password"}' -c - -i
```

# Get user info
```console
curl "http://fs.panictriggers.xyz/api/me" --cookie "sessionToken=sessionToken"
```

# File upload
```console
curl -F 'file=@path/to/file' "http://fs.panictriggers.xyz/api/upload" --cookie "sessionToken=sessionToken" -H "File-Public: true|false"
```

# Personal files
```console
curl "http://fs.panictriggers.xyz/api/me/files" --cookie "sessionToken=sessionToken"
```

# Public files
```console
curl "http://fs.panictriggers.xyz/api/publicFiles" --cookie "sessionToken=sessionToken"
```