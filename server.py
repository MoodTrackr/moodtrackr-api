from http.server import BaseHTTPRequestHandler, HTTPServer
import urllib.parse, json, socket
import bcrypt
import mysql.connector
import hashlib
import time
import ssl
from moodtrackr.engine import predict_emotion
from datetime import datetime
import tornado.escape, tornado.ioloop, tornado.web


mserv = mysql.connector.connect(user='mani', password='asdf', host="localhost", database="manipulate")
cursor = mserv.cursor()


class LoginHandler(tornado.web.RequestHandler):


    def set_default_headers(self):
        self.set_header("Access-Control-Allow-Origin", "*")
        self.set_header("Access-Control-Allow-Headers", "Access-Control-Allow-Headers, Access-Control-Allow-Origin, Content-Type, Access-Control-Request-Method, Access-Control-Request-Headers")
        self.set_header('Access-Control-Allow-Methods', 'POST, GET, OPTIONS')


    def options(self):
        self.set_status(204)
        self.finish()


    def post(self):
        data = tornado.escape.json_decode(self.request.body)
        try:
            username = data["username"]
            pw = data["password"]
            cursor.execute("select * from users where username = '" + username + "';")
            userinfo = cursor.fetchone()
            if bcrypt.checkpw(pw, userinfo[2]):
                # Successful login
                hashstrang = username + pw + str(time.time())
                hashstring = str.encode(hashstrang)
                cookie = hashlib.sha256(hashstring).hexdigest()
                cursor.execute("update users set cookie='" + cookie + "' where username='" + username + "';")
                mserv.commit()
                cookie = {"cookie" : cookie}
                self.write(cookie)
                return
            else:
                raise ValueError("Invalid Pass")
        except:
            self.set_status(401)
            return


class RegisterHandler(tornado.web.RequestHandler):


    def set_default_headers(self):
        self.set_header("Access-Control-Allow-Origin", "*")
        self.set_header("Access-Control-Allow-Headers", "Access-Control-Allow-Headers, Access-Control-Allow-Origin, Content-Type, Access-Control-Request-Method, Access-Control-Request-Headers")
        self.set_header('Access-Control-Allow-Methods', 'POST, GET, OPTIONS')


    def options(self):
        self.set_status(204)
        self.finish()


    def post(self):
        data = tornado.escape.json_decode(self.request.body)
        try:
            username = data["username"]
            pw = data["password"]
            pwhash = bcrypt.hashpw(pw, bcrypt.gensalt(12))
            cursor.execute("select * from users where username = '" + username + "';")
            try:
                temp = cursor.fetchone()
                if temp == None:
                    raise ValueError("HurDur")
            except:
                cursor.execute("insert into users (username, pwhash) values('" + username  + "', '" + pwhash  + "');")
                mserv.commit()
        except:
            self.set_status(400)
            return


class HistoryHandler(tornado.web.RequestHandler):


    def set_default_headers(self):
        self.set_header("Access-Control-Allow-Origin", "*")
        self.set_header("Access-Control-Allow-Headers", "Access-Control-Allow-Headers, Access-Control-Allow-Origin, Content-Type, Access-Control-Request-Method, Access-Control-Request-Headers")
        self.set_header('Access-Control-Allow-Methods', 'POST, GET, OPTIONS')


    def options(self):
        self.set_status(204)
        self.finish()


    def post(self):
        data = tornado.escape.json_decode(self.request.body)
        try:
            cookie = data["cookie"]
            starttime = data["starttime"]/1000
            endtime = data["endtime"]/1000
            starttime = datetime.fromtimestamp(starttime)
            endtime = datetime.fromtimestamp(endtime)
            query = "select * from emotion e join users u on e.uid = u.id where u.cookie = '" + cookie  + "' and e.timestamp between '" + str(starttime)  + "' and '"  + str(endtime) +  "';"
            cursor.execute(query)
            sumemotions = {
                "Angry" : 0,
                "Disgust" : 0,
                "Fear" : 0,
                "Happy" : 0,
                "Sad" : 0,
                "Surprise" : 0,
                "Neutral" : 0
            }
            totalemotions = 0
            emotiongroup = cursor.fetchall()
            for row in emotiongroup:
                sumemotions[row[2]] = sumemotions[row[2]] + 1
                totalemotions = totalemotions + 1
            if totalemotions > 0:
                sumemotions["Angry"] = sumemotions["Angry"] / totalemotions
                sumemotions["Disgust"] = sumemotions["Disgust"] / totalemotions
                sumemotions["Fear"] = sumemotions["Fear"] / totalemotions
                sumemotions["Happy"] = sumemotions["Happy"] / totalemotions
                sumemotions["Sad"] = sumemotions["Sad"] / totalemotions
                sumemotions["Surprise"] = sumemotions["Surprise"] / totalemotions
                sumemotions["Neutral"] = sumemotions["Neutral"] / totalemotions
            self.write(sumemotions)
            return
        except:
            self.set_status(401)
            return


class UploadHandler(tornado.web.RequestHandler):


    def set_default_headers(self):
        self.set_header("Access-Control-Allow-Origin", "*")
        self.set_header("Access-Control-Allow-Headers", "Access-Control-Allow-Headers, Access-Control-Allow-Origin, Content-Type, Access-Control-Request-Method, Access-Control-Request-Headers")
        self.set_header('Access-Control-Allow-Methods', 'POST, GET, OPTIONS')


    def options(self):
        self.set_status(204)
        self.finish()


    def post(self):
        data = tornado.escape.json_decode(self.request.body)
        try:
            cookie = data["cookie"]
            image = data["image"]
            cursor.execute("select id from users where cookie='" + cookie + "';")
            user = cursor.fetchone()
            user = user[0]
            emotion = predict_emotion(image)
            query = "insert into emotion (uid, emotion, timestamp) values('" + str(user) + "', '" + emotion  + "', '" + str(datetime.now()) + "');"
            cursor.execute(query)
            mserv.commit()
            self.write({"emotion": emotion})
            return
        except:
            self.set_status(401)
            return



app = tornado.web.Application([
    (r"/login", LoginHandler),
    (r"/register", RegisterHandler),
    (r"/history", HistoryHandler),
    (r"/upload", UploadHandler)
])


class RedirectHandler(tornado.web.RequestHandler):

    def prepare(self):
        if self.request.protocol == 'http':
            self.redirect('https://' + self.request.host, permanent=False)

    def get(self):
        self.write("Hello, world")


if __name__ == '__main__':
    application = tornado.web.Application([
        (r'/', RedirectHandler)
    ])
    application.listen(80)
    http_server = tornado.httpserver.HTTPServer(app, ssl_options={
            "certfile": "/etc/letsencrypt/live/moodtrackr.com/fullchain.pem",
            "keyfile": "/etc/letsencrypt/live/moodtrackr.com/privkey.pem"
    })
    http_server.listen(8080)
    tornado.ioloop.IOLoop.instance().start()
