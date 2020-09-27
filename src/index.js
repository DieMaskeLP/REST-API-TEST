const fs = require("fs")
const express = require("express")
const app = express()
const db = JSON.parse(fs.readFileSync("Users.json").toString())
const crypto = require('crypto');
let algorithm = 'aes-256-cbc';

function generateKeyIV(){
    return {
        "key": crypto.randomBytes(32),
        "iv": crypto.randomBytes(16)
    }
}

function generateID(){
    let id = ""
    for (let i = 0; i < 6; i++) {
        id += Math.floor(Math.random() * (Math.floor(9)-Math.ceil(0)))
    }
    return !checkJSONDB(id, "id", false) ? id : generateID()
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
    let decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(key), iv);
    let decrypted = decipher.update(encryptedText);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted.toString();
}


let gets = [
    {
        "page": "/",
        "func": function (req, res, next){
            let result = ""
            for (let i = 0; i < gets.length; i++) {
                result += `<a style="background-color: #999999; border: grey 3px solid; display: block; text-align: center; color: aqua; border-radius: 12px" href='${gets[i].page}'>${gets[i].page}</a>`
            }
            res.send(result)
        }
    }
]

let posts = [

]

class RequestsHelper {
    add(page, func) {
        gets.push({
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

    registerModules(){
        for (let i = 0; i < gets.length; i++) {
            app.get(gets[i].page, function (req, res, next){
                console.info({
                    "REQUEST": "GET",
                    "URL": req.url,
                    "CLIENT": req.ip
                })
                gets[i].func(req, res, next)
            })
        }
        for (let i = 0; i < posts.length; i++) {
            app.post(posts[i].page, function (req, res, next){
                console.info({
                    "REQUEST": "POST",
                    "URL": req.url,
                    "CLIENT": req.ip
                })
                posts[i].func(req, res, next)
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

    return (checkJSONDB(req.headers.authorization, "Authorization") !== undefined)


}

let rh = new RequestsHelper()


function checkJSONDB(searchValue, type, forceFalse){
    if (!forceFalse){
        for (let i = 0; i < db.length; i++) {
            if (searchValue == db[i][type]){
                return db[i]
            }

        }
        return undefined
    } else return false
}

rh.add("/api/usr", function (req, res, next) {
    let query = req.query
    if (isAuth(req)){

        let searchQuery = {
            "searchValue": query[Object.keys(query)[0]],
            "type": Object.keys(query)[0]
        }

        let result = checkJSONDB(searchQuery.searchValue, searchQuery.type, (!searchQuery.searchValue))

        if (result){
            res.json({
                status: "200",
                "user": result
            })
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
    let query = req.query, data = req.headers["data"]
    if (isAuth(req)){
        let searchQuery = {
            "searchValue": query[Object.keys(query)[0]],
            "type": Object.keys(query)[0]
        }

        let result = checkJSONDB(searchQuery.searchValue, searchQuery.type, (!searchQuery.searchValue))

        if (result){
            res.json({
                status: "200",
                "user": result
            })
        } else if (searchQuery.searchValue){
                res.json({
                    status: 404,
                    "error": "USER_NOT_FOUND",
                    "message": "Can´t find user to given arguments",
                    "arguments": {
                        "type": searchQuery.type,
                        "searchValue": searchQuery.searchValue
                    }
                })
            } else {

            if (data){
                data = JSON.parse(data)
                db.push(data)
                res.send("Scucces!")
            } else {
                res.json({
                    "status": 500,
                    "message": "Can't create User. Header 'data' is missing",
                    "error": "USER_CAN_NOT_BE_CREATED"
                })
            }

        }




    } else {
        sendNotAuth(res)
    }
})

function sendNotAuth(res, message){
    res.json({
        "status": 401,
        "message": message ? message : "Authorization-Key not accepted",
        "error": "UNAUTHORIZED"
    })
}

rh.startListening(4444)
