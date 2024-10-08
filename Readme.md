# Api documentation

## Login 
- to login you have to provide email and password 
- example 
```
    POST http://127.0.0.1:8000/api/login
    Content-Type: application/json

    {
        "email":"dijad7190@esterace.com",
        "password":"aoutifra1"
    }
```

## Sign up 
- manual signup 
- example 
```
    POST http://127.0.0.1:8000/api/signup
    Content-Type: application/json

    {
        "first_name":"flirsts_name",
        "last_name":"firsmt_sname",
        "email":"email0@email.com",
        "password":"password",
        "password1":"password1"
    }
```

## Oauth Sign up 
- intra link = https://api.intra.42.fr/oauth/authorize?client_id=u-s4t2ud-b7a07e95a71b24423b13ff59e31449be4182b63b7aaf9bc87dcd54d2be5e83ec&redirect_uri=http%3A%2F%2F127.0.0.1%3A8000%2Fapi%2Fcallback&response_type=code

- callback link = 'http://127.0.0.1:8000/api/callback'


## Get User Info 
- 
```
    GET http://127.0.0.1:8000/api/user_info
    Content-Type: application/json
    Authorization: Bearer TOKEN
    
    {
        "email":"email0@email.com"
    }
```



 