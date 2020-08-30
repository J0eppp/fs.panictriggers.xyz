# Login
```curl -X POST "http://fs.panictriggers.xyz/api/login" -H "Content-Type: application/json" -d '{"username": "username", "password": "password"}' -c - -i```

# Get user info
```curl "http://fs.panictriggers.xyz/api/me" --cookie "sessionToken=sessionToken"```

# File upload
```curl -F 'file=@./tempfile.txt' "http://fs.panictriggers.xyz/api/upload" --cookie "sessionToken=sessionToken" -H "File-Public: true|false"```

# Personal files
```curl "http://fs.panictriggers.xyz/api/me/files" --cookie "sessionToken=sessionToken"```

# Public files
```curl "http://fs.panictriggers.xyz/api/publicFiles" --cookie "sessionToken=sessionToken"```