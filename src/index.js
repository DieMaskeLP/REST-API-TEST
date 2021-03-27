const fs = require("fs")
const express = require("express")
const app = express()
let db = []

const DiscordBot = require("C:\\Users\\Fred\\WebstormProjects\\rank-dc-bot\\bot.js")

const API_LEVELS = {
    "FULL-API": "2",
    "PUBLIC-API": "1",
    "undefined": "0"
}


app.use(express.json({extended: false}))
app.use(express.urlencoded({ extended: true }))

const crypto = require('crypto');

function generateKeyIV(){
    return {
        "key": crypto.randomBytes(32),
        "iv": crypto.randomBytes(16)
    }
}

function generateAuthorizationKey(){
    let key = crypto.randomBytes(18).toString("hex")
    return checkJSONDB(key, "Authorization", false).length === 0 ? key : generateAuthorizationKey()
}

function generateID(){
    let id = ""
    for (let i = 0; i < 6; i++) {
        id += Math.floor(Math.random() * (Math.floor(9)-Math.ceil(0)))
    }
    return checkJSONDB(id, "id", false).length === 0 ? id : generateID()
}

function checkEmailExists(email){
    return checkJSONDB(email, "email", false).length === 0
}

function encrypt(text, key, iv) {
    let cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(key), iv);
    let encrypted = cipher.update(text);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return encrypted.toString('hex')
}

function decrypt(text, key, iv) {
    iv = Buffer.from(iv, 'hex');
    let encryptedText = Buffer.from(text, 'hex');
    let decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(key, "hex"), Buffer.from(iv, "hex"));
    let decrypted = decipher.update(encryptedText);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted.toString();
}

function writeDB(){
    fs.writeFileSync("Users.json", JSON.stringify(db))
}

function updateDB(){
    db = JSON.parse(fs.readFileSync("Users.json").toString())
}

function decryptPassword(credentials){
    return decrypt(credentials["password"], credentials["key"], credentials["iv"])
}

function createUser(data){
    let credentials = generateKeyIV()
    console.log(credentials.iv)
    console.log(credentials.iv.toString("hex"))
    console.log(Buffer.from(credentials.iv.toString("hex"), "hex"))
    return {
        "authorization-level": "0", //Standard Auth Level,
        "Authorization": generateAuthorizationKey(),
        "credentials": {
            "key": credentials.key.toString("hex"),
            "iv": credentials.iv.toString("hex"),
            "password": encrypt("@12Fritz", credentials.key, credentials.iv), //Enrypted password !REQUIRED!,
        },
        "public-data": {
            "id": generateID(),
            "username": (data["username"] ? data["username"] : "null"), //REQUIRED or EMAIL
            "email": (data["email"] ? data["email"] : "null") //REQUIRED or USERNAME
        }
    }
}

function sendNotAuth(res, message){
    res.json({
        "status": 401,
        "message": message ? message : "Authorization-Key not accepted",
        "error": "UNAUTHORIZED"
    })
}


let gets = [
    {
        "page": "/",
        "func": function (req, res, next){
            let result = ""
            for (let i = 0; i < gets.length; i++) {
                result += `<a href='${gets[i].page}'>${gets[i].page}</a>`
            }
            res.send(result)
        }
    }
], posts = [], puts = [], deletes = []

class RequestsHelper {
    addGet(page, func) {
        gets.push({
            "page": page,
            "func": func
        })
    }

    addPut(page, func){
        puts.push({
            "page": page,
            "func": func
        })
    }

    addPost(page, func) {
        posts.push({
            "page": page,
            "func": func
        })
    }

    addDelete(page, func){
        deletes.push({
            "page": page,
            "func": func
        })
    }
    registerModules(){
        for (let i = 0; i < gets.length; i++) {
            app.get(gets[i].page, function (req, res, next){
                updateDB()
                gets[i].func(req, res, next)
                writeDB()
                updateDB()
            })
        }
        for (let i = 0; i < posts.length; i++) {
            app.post(posts[i].page, function (req, res, next){
                updateDB()
                posts[i].func(req, res, next)
                writeDB()
                updateDB()
            })
        }
        for (let i = 0; i < puts.length; i++) {
            app.put(puts[i].page, function (req, res, next){
                updateDB()
                puts[i].func(req, res, next)
                writeDB()
                updateDB()
            })
        }
        for (let i = 0; i < deletes.length; i++) {
            app.delete(deletes[i].page, function (req, res, next){
                updateDB()
                deletes[i].func(req, res, next)
                writeDB()
                updateDB()
            })
        }
    }

    startListening(port){
        this.registerModules()
        app.listen(port)
    }

    stopListening(){
        app.stop()
    }
}

function isAuth(req){
    if (req.headers.authorization === undefined){
        return {
            "isAuth": false,
            "authorization-level": "0"
        }
    }

    let dbEntry = checkJSONDB(req.headers.authorization, "Authorization")

    if (dbEntry.length > 0){
        dbEntry = dbEntry[0]
    } else {

        return {
            "isAuth": false,
            "authorization-level": "0"
        }
    }

    return {
        "isAuth": dbEntry,
        "authorization-level": (dbEntry === undefined ? "0" : dbEntry["authorization-level"])
    }
}

let rh = new RequestsHelper

function getPositionDB(searchValue, type){
    let result = []
    for (let i = 0; i < db.length; i++) {
        if (searchValue == db[i][type] || db[i]["public-data"][type] == searchValue){
            result.push(i)}

    }
    return result

}

function checkJSONDB(searchValue, type, forceFalse){
    let result = []
    if (!forceFalse){
        for (let i = 0; i < db.length; i++) {
            if (searchValue == db[i][type] || db[i]["public-data"][type] == searchValue){
                result.push(db[i])
            }

        }
        return result
    } else return false
}

rh.addGet("/api/usr", function (req, res, next) {
    let query = req.query
    let auth = isAuth(req)
    if (auth["isAuth"]){

        let searchQuery = {
            "searchValue": query[Object.keys(query)[0]],
            "type": Object.keys(query)[0],
        }

        let result = checkJSONDB(searchQuery.searchValue, searchQuery.type, (!searchQuery.searchValue))


        if (result){
            if (auth["authorization-level"] === API_LEVELS["FULL-API"]){
                res.json({
                    "status": 200,
                    "user": result
                })
            } else if (auth["authorization-level"] === API_LEVELS["PUBLIC-API"]){
                let resUser = []

                for (let i = 0; i < result.length; i++) {
                    resUser.push(result[i]["public-data"])
                }

                res.json({
                    "status": 200,
                    "user": resUser
                })
            } else if (auth["authorization-level"] === API_LEVELS.undefined){
                sendNotAuth(res, "Authorization-Level is set to none. Please contact an Administrator or Developer")
            }
        } else if (searchQuery["type"] === undefined){
            if (auth["authorization-level"] === API_LEVELS["FULL-API"]){
                res.json(db)
            } else if (auth["authorization-level"] === API_LEVELS["PUBLIC-API"]){
                let users = []
                for (let i = 0; i < db.length; i++) {
                    users.push(db[i]["public-data"])
                }
                res.json(users)
            } else if (auth["authorization-level"] === API_LEVELS["undefined"]){
                sendNotAuth(res)
            }
        } else {
            res.json({
                status: 404,
                "error": "USER_NOT_FOUND",
                "message": "Can´t find user to given arguments",
                "arguments": {
                    "type": searchQuery.type,
                    "searchValue": searchQuery.searchValue
                }
            })
        }

    } else {
        sendNotAuth(res)
    }
})

rh.addPost("/api/usr", function (req, res, next){
    let data = req.headers["data"]
    let auth = isAuth(req)
    if (auth["isAuth"]){
        data = JSON.parse(data)
        if (data){
            switch (auth["authorization-level"]){
                case API_LEVELS["FULL-API"]:
                    if (data["username"] !== undefined || data["email"] !== undefined && data["password"] !== undefined){

                        if (data["email"] !== undefined){
                            if (checkEmailExists(data["email"])){
                                res.json({
                                    "status": "404",
                                    "message": "Email Address already in use",
                                    "error": "ADDRESS_ALREADY_IN_USE"
                                })
                                return
                            }
                        }

                        let newUser = createUser(data)

                        res.json({
                            "status": 200,
                            "message": "User created",
                            "user": newUser
                        })

                        db.push(newUser)
                    } else {
                        res.json({
                            "status": "idk",
                            "error": "MISSING_ARGUMENTS",
                            "message": "Header 'data' is missing arguments",
                            "arguments": data,
                            "requiredArguments": {
                                "password": "Always required",
                                "username": "Required or Email",
                                "email": "Required or Username"
                            }
                        })
                    }

                    break
                default:
                    res.json({
                        "status": 401,
                        "error": "AUTHORIZATION-LEVEL_NOT_REACHED",
                        "message": "You are not AUTORISIERT to do this",
                        "authorization_required": API_LEVELS["FULL-API"],
                        "your_authorization": auth["authorization-level"]
                    })
                    break
            }
        } else {
            res.json({
                "status": "404",
                "error": "USER_DATA_MISSING",
                "message": "User data could not be founded"
            })
        }

    } else {
        sendNotAuth(res)
    }
})

rh.addGet("/api/login", function (req, res, next){
    let auth = isAuth(req)
    if (auth["isAuth"]){
        if (auth["authorization-level"] === API_LEVELS["FULL-API"]){

            let data = req.headers["data"]

            if (data !== []){
                let result

                if (data.startsWith("\"")){
                    data.slice(1, -1)
                }
                data = JSON.parse(data)
                if (data["password"] === undefined){
                    res.json({
                        "status": "404",
                        "error": "REQUIRED_ARGS_NOT_FOUND",
                        "message": "Required Arguments are not given",
                        "required": {
                            "password": "Always required",
                            "email": "Only required if username is not given",
                            "username": "Only required if email is not given"
                        }
                    })
                    return
                }

                if (data["email"] !== undefined){
                    result = checkJSONDB(data["email"], "email")
                    if (result.length > 0){
                        result = result[0]
                    } else {
                        res.json({
                            "status": "401",
                            "message": "Login credentials not correct",
                            "error": "LOGIN_CREDENTIALS_WRONG"
                        })
                        return;
                    }
                } else if (data["username"] !== undefined){
                    result = checkJSONDB(data["username"], "username")
                    if (result.length > 0){
                        result = result[0]
                    } else {
                        res.json({
                            "status": "401",
                            "message": "Login credentials not correct",
                            "error": "LOGIN_CREDENTIALS_WRONG"
                        })
                        return;
                    }
                } else {
                    res.json({
                        "status": "404",
                        "error": "REQUIRED_ARGS_NOT_FOUND",
                        "message": "Required Arguments are not given",
                        "required": {
                            "password": "Always required",
                            "email": "Only required if username is not given",
                            "username": "Only required if email is not given"
                        }
                    })
                }


                if (result !== []){

                    if (data["password"] === decryptPassword({"key": result["credentials"]["key"], "iv": result["credentials"]["iv"], "password": result["credentials"]["password"]})) {

                    } else {
                        res.json({
                            "status": "200",
                            "message": "Login successful"
                        })
                    }

                } else {
                    res.json({
                        "status": "404",
                        "error": "USER_NOT_FOUND",
                        "message": "Login Credentials were not found",
                    })
                }

            } else {
                res.json({
                    "status": "404",
                    "error": "USER_DATA_MISSING",
                    "message": "User data could not be founded"
                })
            }
        } else {
            sendNotAuth(res, "Required API_LEVEL 2")
        }
    } else {
        sendNotAuth(res)
    }
})


rh.addPut("/api/usr", function (req, res, nex){
    let auth = isAuth(req)
    if (auth["isAuth"]){
        let id = req.query["id"]
        if (id){

            let data = req.headers["data"]
            let result = checkJSONDB("id", id)

            if (result === []){
                res.json({
                    "status": "404",
                    "error": "USER_NOT_FOUND",
                    "message": "User could not find to id",
                    "arguments": req.query
                })
                return;
            }

            if (data === undefined){
                res.json({
                    "status": "404",
                    "error": "DATA_NOT_FOUND",
                    "message": "Header 'data' could not be founded"
                })
                return
            }

            if (auth["authorization-level"] === API_LEVELS["FULL-API"]){



            } else if (auth["authorization-level"] === API_LEVELS["PUBLIC-API"]){





            } else if (auth["authorization-level"] === API_LEVELS.undefined){
                sendNotAuth(res)
            } else {
                res.json({
                    "status": "wtf?",
                    "message": "Could not recognize 'authorization-level'",
                    "error": "AUTH_LEVEL_NOT_FOUND"
                })
            }
        } else {
            res.json({
                "status": "404",
                "error": "ID_NOT_FOUND",
                "message": "Could not find ID in the query"
            })
        }

    } else {
        sendNotAuth(res)
    }
})

rh.addDelete("/api/usr", function (req, res, next){
    let auth = isAuth(req)

    if (auth["isAuth"]){

    } else {
        sendNotAuth(res)
    }

})


rh.addPost("/5ivesouls/games", function (req, res, next){
    let auth = isAuth(req)
    if (auth["isAuth"]){
        let query = req.headers
        let game = JSON.parse(query["game"])
        if (game !== undefined) {
            if (game["uid"] === undefined || game["uid"] === null){
                game["uid"] = DiscordBot.generateUID()
            }
        } else {
            res.status(404).send()
            return
        }
        DiscordBot.postGame(game).then((game) => {
            res.status(200).json(game.getGameAsJSONString())
        })
    } else {
        sendNotAuth(res)
    }
})


rh.addGet("/5ivesouls/games", function (req, res, next){
    let auth = isAuth(req)

    if (auth["isAuth"]){

        let headers = req.headers
        let uid = headers["uid"]
        if (uid === undefined){
            res.status(404).json({
                "error": "Game-ID not found"
            })
            return
        }

        if (!DiscordBot.existsGameID(uid)){
            res.status(404).json({"error": "Game-ID does not exists"})
            return;
        }

        let game = new DiscordBot.GameManager(uid).getGameAsJSONString()
        res.json(game)

    } else {
        sendNotAuth(res)
    }


})

//start SERVER and DB

updateDB()
writeDB()


DiscordBot.login().then(() => {

})


rh.startListening(4556)
