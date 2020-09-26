const fs = require("fs")
const app = require("express")()
const db = new Map(fs.readFileSync("Users.json").toString().toJSON())
console.log(db)


let gets = [
    {
        "page": "/",
        "func": function (res, req, next) {
            req.json({
                "state": "success",
                "message": "This does work"
            })
        }
    }
]

class RequestsHelper {
    add(page, func) {
        gets.push({
            "page": page,
            "func": func
        })
    }

    registerModules(){
        for (let i = 0; i < gets.length; i++) {
            app.get(gets[i].page, function (req, res, next){
                gets[i].func(req, res, next)
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

function isAuth(req, key){

    if (req.headers.auth === key){
        return true
    } else return false
}

let rh = new RequestsHelper()

rh.add(
    "/hello",
    function (req, res, next) {

        res.json(
            {
                "state": "success",
                "message": "Hello World wide Web"
            }
        )
    }
)



rh.add("/api/usr", function (req, res, next) {
    if (isAuth(req, fs.readFileSync("./Auth.key").toString())){
        let query = req.query
        console.log(query)
        if (db.has(query.username)){
            let user = db.get(query[0].username)
            res.json({
                "user":{
                    user
                }
            })
        } else {
            res.json({
                "status": 404,
                "error": "USR_NOT_FOUND",
                "message": "Username can not be founded!"
            })
        }

    } else {
        res.json({
            "status": 500,
            "error": "Auth-key not correct",
        })
    }
})


rh.startListening(4556)
