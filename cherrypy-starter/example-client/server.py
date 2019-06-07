import ast
import base64
import json
import sqlite3
import threading
import time
import urllib.request
from queue import Queue
from subprocess import check_output
from threading import Event

import cherrypy

import nacl.bindings
import nacl.encoding
import nacl.pwhash
import nacl.secret
import nacl.signing
import nacl.utils
from bs4 import BeautifulSoup
from nacl.public import Box, PrivateKey
from queue import Queue

e=threading.Event()
user=""
headers=""
pubkey_hex_str=""
startHTML = """
<html>
    <head>
        <title>ksae900's web client</title> 
        <link rel="stylesheet" type="text/css" href="default.css">
    </head>
    <body>
"""
DefaultHeader="""
            <div id="navbar">
            <a href="/about">About</a>
            <a href="/">Home</a>
            <a href="/login">Login</a>
            </div><script src="default.js"></script>
            <div class="content">"""
LoginHeader="""
            <div id="navbar">
            <a href="/about">About</a>
            <a href="/">Home</a>
            <a href="/private_messages">PM's</a>
            <a href="/signout">Log Out</a>
            <a href="/message">Message</a>
            <a href="/users">Users</a>
            <a href="/account">"""+user+"""</a>
            </div><script src="default.js"></script>
            <div class="content">"""
endHTML="</div></body></html>"
class ApiApp(object):
    # CherryPy Configuration
    _cp_config = {'tools.encode.on': True,
                  'tools.encode.encoding': 'utf-8',
                  'tools.sessions.on': 'True',
                  'request.dispatch': cherrypy.dispatch.MethodDispatcher(),
                  'tools.response_headers.on': True,
                  'tools.response_headers.headers': [('Content-Type', 'application/json; charset=utf-8')],
                  }

    @cherrypy.expose
    @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    def ping_check(self):
        payload={ "response": "ok", "my_time":str(time.time())}
        return payload
     
    @cherrypy.expose
    @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    def rx_broadcast(self):
        data = cherrypy.request.json
        message=data['message']
        print(message)
        pubkey=data['loginserver_record'].split(',')[1]
        credentials = ('%s:%s' % ("ksae900", "kaplunket_776423926"))
        b64_credentials = base64.b64encode(credentials.encode('ascii'))
        headers = {
            'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
            'Content-Type': 'application/json; charset=utf-8',
        }
        JSON=check_pubkey(headers,pubkey)
        print(JSON)
        if JSON['loginserver_record']==data['loginserver_record']:
            conn = sqlite3.connect("my.db")
            c = conn.cursor() 
            
            c.execute("""SELECT COUNT (id)  FROM pubmessages;""")
            result=c.fetchone()
            int(result[0])
            
            c.execute("INSERT INTO pubmessages (id,message,recieved_at,sender)VALUES (?,?,?,?)",(str(int(result[0])+1), str(data),str(time.time()),data['loginserver_record'].split(',')[0],))
            conn.commit()
                
            conn.close()

            payload={ "response": "ok"}
        else:
            payload={ "response": "error",'message':'Invalid loginserver_record'}
        return payload
        
    @cherrypy.expose
    @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    def rx_privatemessage(self,data="",headers=""):
        data = cherrypy.request.json
        pubkey=data['loginserver_record'].split(',')[1]
        credentials = ('%s:%s' % ("ksae900", "kaplunket_776423926"))
        b64_credentials = base64.b64encode(credentials.encode('ascii'))
        headers = {
            'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
            'Content-Type': 'application/json; charset=utf-8',
        }
        JSON=check_pubkey(headers,pubkey)
        if JSON['loginserver_record']==data['loginserver_record']:
            conn = sqlite3.connect("priv.db")
            cur = conn.cursor() 
            
            cur.execute("""SELECT COUNT (id)  FROM privmessages;""")
            result=cur.fetchone()
            int(result[0])
            
            cur.execute("INSERT INTO privmessages (id,message,recieved_at,sender)VALUES (?,?,?,?)",(str(int(result[0])+1), str(data),str(time.time()),data['loginserver_record'].split(',')[0],))
            conn.commit()
                
            conn.close()
            
            payload={ "response": "ok"}
        else:
            payload={ "response": "error",'message':'Invalid loginserver_record'}
        return payload
        
    @cherrypy.expose
    @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    def checkmessages(self,since="0"):
        since=float(since)
        pubmessages=[]
        privmessages=[]
        
        conn = sqlite3.connect("my.db")
        #get the cursor (this is what we use to interact)
        cur = conn.cursor() 
        cur.execute("SELECT id,message,recieved_at,sender FROM pubmessages")
        rows = cur.fetchall()
        for row in rows:
            if float((ast.literal_eval(row[1]))['sender_created_at'])>=since:
                pubmessages.append(ast.literal_eval(row[1]))
        conn.close()
        
        c = sqlite3.connect("priv.db")
        #get the cursor (this is what we use to interact)
        cur = c.cursor() 
        cur.execute("SELECT id,message,recieved_at,sender FROM privmessages")
        rows = cur.fetchall()
        for row in rows:
            if float((ast.literal_eval(row[1]))['sender_created_at'])>=since:
                privmessages.append(ast.literal_eval(row[1]))
        c.close()    
        
        payload={ "response": "ok", "broadcasts":pubmessages,"private_messages":privmessages}
        return payload
        
    @cherrypy.expose
    @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    def rx_groupmessage(self):
        print()
        
    @cherrypy.expose
    @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    def rx_groupinvite(self):
        print()

class MainApp(object):

        # CherryPy Configuration
    _cp_config = {'tools.encode.on': True,
                  'tools.encode.encoding': 'utf-8',
                  'tools.sessions.on': 'True',
                  }
    
    # If they try somewhere we don't know, catch it here and send them to the right place.
    @cherrypy.expose
    def default(self, *args, **kwargs):
        """The default page, given when we don't recognise where the request is for."""
        Page = startHTML + "I don't know where you're trying to go, so have a 404 Error."
        cherrypy.response.status = 404
        return Page

    # PAGES (which return HTML that can be viewed in browser)
    @cherrypy.expose
    def index(self,search=""):
        Page=startHTML
        try:
            user=cherrypy.session['username']
            Page += LoginHeader
            Page +=  "<p><h3>Welcome! This is a test website for COMPSYS302!</h3><br/>"
            Page += "Hello " + user + "!<br/>"
            Page += "Here is some bonus text because you've logged in! HERE IS SOME EXTRA TEXT AGAIN! <a href='/signout'>Sign out</a>"
            
            Page += '<form action="/" method="post" enctype="multipart/form-data">'
            Page += 'Search: <input id="bar" size="50" type="text" name="search"/>'
            Page += '<input type="submit" value="Search"/></form>'
            
            conn = sqlite3.connect("my.db")
            #get the cursor (this is what we use to interact)
            cur = conn.cursor() 
            cur.execute("SELECT id,message,recieved_at,sender FROM pubmessages")
            array=[]
            rows = cur.fetchall()
            for row in rows:
                temp=""
                message=ast.literal_eval(row[1])['message']
                user = ast.literal_eval(row[1])['loginserver_record'].split(",")[0]
                if(message.find("!Meta:")==-1):
                    VALID_TAGS = ['strong', 'em', 'ul', 'li', 'br','img','iframe']
                    soup = BeautifulSoup(message)

                    for tag in soup.findAll(True):
                        if tag.name not in VALID_TAGS:
                            tag.hidden = True
                    cleaned_text=soup.renderContents().decode('utf-8')
                    
                    temp1=cleaned_text
                    temp2=""
                    while not(cleaned_text.find('![') == -1):
                        if not(cleaned_text.split('![')[1].find('](https://')==-1):
                            description=cleaned_text.split('![')[1].split('](https://')[0]
                            if not(cleaned_text.split('![')[1].split('](https://')[1].find(')')==-1):
                                link="https://"+cleaned_text.split('![')[1].split('](https://')[1].split(')')[0]
                                temp2+="<img src='"+link+"' alt='"+description+"'></img>"
                                cleaned_text=cleaned_text.split('![')[1].split('](https://')[1].split(')')[1]
                            else:
                                temp2+= ("!["+(cleaned_text.split('![')[1]).split('](https://')[0]+"](https://")
                                cleaned_text=cleaned_text.split('![')[1].split('](https://')[1]
                        else:
                            temp2+=cleaned_text.split('![')[0]+"!["
                            cleaned_text=cleaned_text.split('![')[1]
                    if (len(temp2)==0):
                        message=temp1
                    else:
                        message=temp2
                    if len(search)>0:
                        if not(user.find(search)==-1 and message.find(search)==-1):
                            temp +=  "<p><div id='messageHeading'><h3>"+user+"</h3>"
                            temp += "</br><div id='message'><p class='c'word-break: break-all;>"+message+"</p></div></div><br/>"
                            array.append(temp)
                    else:
                        temp +=  "<p><div id='messageHeading'><h3>"+user+"</h3>"
                        temp += "</br><div id='message'><p class='c'word-break: break-all;>"+message+"</p></div></div><br/>"
                        array.append(temp)
                else:
                    #Meta stuff here later
                    print()
            for i in reversed(array):
                Page += i
            conn.close()
            
        except KeyError:
            Page += DefaultHeader
            Page +=  "<p><div id='messageHeading'><h3>Welcome! This is a test website for COMPSYS302! This is also a message heading, normally usernames will be here</h3>"
            Page += "</br><div id='message'><p>heres some text to serve as the messages contents</p></div></div><br/>"
            Page += "Click here to <a href='login'>login</a>, alternatively use the button at the top."
        Page += "<br/><br/><br/><br/><br/><br/><br/><br/><br/><br/><br/><br/><br/><br/><br/><br/><br/><br/><br/><br/><br/><br/><br/><br/><br/><br/><br/><br/><br/><br/><br/><br/><br/><br/><br/><br/><br/><br/><br/>Some text down here to show scrolling</p>"
        Page += endHTML
        return Page
    
    @cherrypy.expose
    def private_messages(self,search=""):
        Page=startHTML
        try:
            user=cherrypy.session['username']
            Page += LoginHeader
            Page +=  "<p><h1>Welcome to private messages sent to :"+user+"</h1><br/>"
            Page += '<form action="/private_messages" method="post" enctype="multipart/form-data">'
            Page += 'Search: <input id="bar" size="50" type="text" name="search"/>'
            Page += '<input type="submit" value="Search"/></form>'
            conn = sqlite3.connect("priv.db")
            #get the cursor (this is what we use to interact)
            array=[]
            cur = conn.cursor() 
            cur.execute("SELECT id,message,recieved_at,sender FROM privmessages")
            rows = cur.fetchall()
            for row in rows:
                temp=""
                message=ast.literal_eval(row[1])['encrypted_message']
                user = ast.literal_eval(row[1])['loginserver_record'].split(",")[0]
                pubkey=ast.literal_eval(row[1])['loginserver_record'].split(",")[1]
                try:
                    VF=cherrypy.session['prikey']
                    PK = VF.to_curve25519_private_key()
                    box = nacl.public.SealedBox(PK)
                    message=box.decrypt(message.encode('utf-8'), encoder=nacl.encoding.HexEncoder).decode('utf-8')
                    
                    if(message.find("!Meta:")==-1):
                        VALID_TAGS = ['strong', 'em', 'ul', 'li', 'br','img','iframe']
                        soup = BeautifulSoup(message)

                        for tag in soup.findAll(True):
                            if tag.name not in VALID_TAGS:
                                tag.hidden = True
                        cleaned_text=soup.renderContents().decode('utf-8')
                                
                        temp1=cleaned_text
                        temp2=""
                        while not(cleaned_text.find('![') == -1):
                            if not(cleaned_text.split('![')[1].find('](https://')==-1):
                                description=cleaned_text.split('![')[1].split('](https://')[0]
                                if not(cleaned_text.split('![')[1].split('](https://')[1].find(')')==-1):
                                    link="https://"+cleaned_text.split('![')[1].split('](https://')[1].split(')')[0]
                                    temp2+="<img src='"+link+"' alt='"+description+"'></img>"
                                    cleaned_text=cleaned_text.split('![')[1].split('](https://')[1].split(')')[1]
                                else:
                                    temp2+= ("!["+(cleaned_text.split('![')[1]).split('](https://')[0]+"](https://")
                                    cleaned_text=cleaned_text.split('![')[1].split('](https://')[1]
                            else:
                                temp2+=cleaned_text.split('![')[0]+"!["
                                cleaned_text=cleaned_text.split('![')[1]
                        if (len(temp2)==0):
                            message=temp1
                        else:
                            message=temp2
                            
                        if len(search)>0:
                            if not(user.find(search)==-1 and message.find(search)==-1):
                                temp +=  "<p><div id='messageHeading'><h3>"+user+"</h3>"
                                temp += "</br><div id='message'><p class='c'word-break: break-all;>"+message+"</p></div>"
                                temp += "<a href=p2p?user="+ user+"&pubkey="+ pubkey+"&address=*>Reply</a>"+"</div><br/>"
                                array.append(temp)
                        else:
                            temp +=  "<p><div id='messageHeading'><h3>"+user+"</h3>"
                            temp += "</br><div id='message'><p class='c'word-break: break-all;>"+message+"</p></div>"
                            temp += "<a href=p2p?user="+ user+"&pubkey="+ pubkey+"&address=*>Reply</a>"+"</div><br/>"
                            array.append(temp)
                    else:
                        #META stuff
                        print()
                except:
                    continue
            conn.close()
            for i in reversed(array):
                Page += i 
        except KeyError:
            raise cherrypy.HTTPRedirect('/')
        Page += endHTML
        return Page 
    
    @cherrypy.expose
    def about(self):
        Page=startHTML
        try:
            user=cherrypy.session['username']
            Page += LoginHeader
            Page +=  "<h1>Hi there " + user + ", this is a website made by ksae900 for a compsys 302 assignment</h1><br/>"
            Page += "Here is some bonus text because you've logged in! HERE IS SOME EXTRA TEXT AGAIN! <a href='/signout'>Sign out</a>"
        except KeyError:
            Page += DefaultHeader
            Page +=  "<h1>Hi there, this is a website made by ksae900 for a compsys 302 assignment</h1><br/>"
            Page += "Click here to <a href='login'>login</a>, alternatively use the button at the top."
        Page += "<br/><br/><br/><br/><br/><br/><br/><br/><br/><br/><br/><br/><br/><br/><br/><br/><br/><br/><br/><br/><br/><br/><br/><br/><br/><br/><br/><br/><br/><br/><br/><br/><br/><br/><br/><br/><br/><br/><br/>Some text down here to show scrolling</p>"
        Page += endHTML
        return Page
    
    
    @cherrypy.expose
    def message(self):
        try:
            cherrypy.session['username']
        except KeyError:
            raise cherrypy.HTTPRedirect('/')
        Page = startHTML +LoginHeader +"<test><h1>Public Messasging</h1>"
        Page += '<form autocomplete="off" action="/public" method="post" enctype="multipart/form-data">'
        Page += 'Message: <textarea palceholder="Type your message here" name="message" rows="3" cols="50" size="50" type="text"> </textarea><br/>'
        Page += '<input type="submit" value="Submit"/></form>'
        Page += "</test>"
        Page += endHTML
        return Page
    
    @cherrypy.expose
    def private(self,user="",pubkey="",address="",message=""):
        try:
            cherrypy.session['username']
        except KeyError:
            raise cherrypy.HTTPRedirect('/')
        
        headers=make_headers(cherrypy.session['username'],cherrypy.session['api_key'])
        
        signing_key1=cherrypy.session['prikey']
        #seems to always make the same public key, no salt i guess
        verify_key1=generatePublicKey(signing_key1)
        # Serialize the verify key to send it to a third party
        pubkey_hex = verify_key1.encode(encoder=nacl.encoding.HexEncoder)
        pubkey_hex_str = pubkey_hex.decode('utf-8')
        record=getLoginserverRecord(headers,cherrypy.session['username'],pubkey_hex_str)
        target_pubkey=nacl.signing.VerifyKey(pubkey.encode('utf-8'), encoder=nacl.encoding.HexEncoder)
        
        privateMessage(headers,record,target_pubkey,user,message,signing_key1,address)
        raise cherrypy.HTTPRedirect('/')
    
    @cherrypy.expose
    def p2p(self,user="",pubkey="",address=""):
        global pubkey_hex_str
        try: 
            cherrypy.session['username']
        except KeyError:
            raise cherrypy.HTTPRedirect('/')
        
        Page = startHTML +LoginHeader +"<test><h1>Private Messaging to:"+user+"</h1>"
        if address=="*":
            headers=make_headers(cherrypy.session['username'],cherrypy.session['api_key'])
            JSON=getUsers(headers)['users']
            for i in JSON:
                if (i['username']==user):
                    address=i['connection_address']
            if address=="*":
                #user not online
                Page +="<h2>This user is not online right now</h2>"
            else:
                Page += '<form autocomplete="off" action="/private" method="post" enctype="multipart/form-data">'
                Page += '<input type="hidden" name="user" value=' + user + ' />'
                Page += '<input type="hidden" name="pubkey" value=' + pubkey + ' />'
                Page += '<input type="hidden" name="address" value=' + address + ' />'
                Page += 'Message: <textarea palceholder="Type your message here" name="message" rows="3" cols="50" size="50" type="text"> </textarea><br/>'
                Page += '<input type="submit" value="Submit"/></form>'
                Page += "</test>"
        else:
            Page += '<form autocomplete="off" action="/private" method="post" enctype="multipart/form-data">'
            Page += '<input type="hidden" name="user" value=' + user + ' />'
            Page += '<input type="hidden" name="pubkey" value=' + pubkey + ' />'
            Page += '<input type="hidden" name="address" value=' + address + ' />'
            Page += 'Message: <textarea palceholder="Type your message here" name="message" rows="3" cols="50" size="50" type="text"> </textarea><br/>'
            Page += '<input type="submit" value="Submit"/></form>'
            Page += "</test>"
        Page += endHTML
        return Page
    
    @cherrypy.expose
    def users(self):
        headers=make_headers(cherrypy.session['username'],cherrypy.session['api_key'])
        try:
            cherrypy.session['username']
        except KeyError:
            raise cherrypy.HTTPRedirect('/')
        Page = startHTML +LoginHeader

        Page += "<ul>"
        userList=getUsers(headers)
        for i in userList["users"]:
            Page +="""<li onclick="location.href = 'p2p?user=""" + i['username'] + "&pubkey="+ i['incoming_pubkey']+ "&address="+i['connection_address']+"""';">"""
            Page += i['username']+" Status: "+i['status']+" Connection address: "+i['connection_address'] 
            Page +='</li></br>'
        Page += "</ul>"
        return Page
    
    @cherrypy.expose
    def public(self,message=""):
        headers=make_headers(cherrypy.session['username'],cherrypy.session['api_key'])
        publicMessage(headers,message,cherrypy.session['prikey'])
        raise cherrypy.HTTPRedirect('/')
    
    @cherrypy.expose
    def serverOffline(self):
        try:
            user=cherrypy.session['username']
            Page = startHTML+LoginHeader
        except KeyError:
            Page = startHTML+DefaultHeader
        Page += "The login server is unavailable or down for maintainence, please try again later"
        Page += "<br> Sorry for the inconvenience, once we have been notified we will contact the server owner<br/>"
        Page += endHTML
        return Page
    
    @cherrypy.expose
    def login(self, bad_attempt=0):
        Page = startHTML+DefaultHeader+"<div id='login'>"
        Page += "<h1>Sign in to your account</h1>"
        Page += "<test><b>"
        Page += '<form action="/signin" method="post" enctype="multipart/form-data">'
        if bad_attempt != 0:
            Page += "<font color='red'>Invalid username/password!</font><br/>"
        Page += 'Username: <input id="bar" size="50" type="text" name="username"/><br/>'
        Page += 'Password: <input id="bar" size="50" type="text" name="password"/><br/>'
        Page += 'Encryption: <input id="bar" size="50" type="text" name="unique"/><br/>'
        Page += '<input type="submit" value="Login"/></form>'
        Page += "</b></test></div>"
        Page += endHTML
        return Page

    @cherrypy.expose
    def sum(self, a=0, b=0):  # All inputs are strings by default
        output = int(a)+int(b)
        return str(output)
    
    @cherrypy.expose
    def profile(self):  # All inputs are strings by default
        Page = startHTML+DefaultHeader
        Page += endHTML
        return Page

    # LOGGING IN AND OUT
    @cherrypy.expose
    def signin(self, username=None, password=None,unique=None):
        """Check their name and password and send them either to the main page, or back to the main login screen."""
        key=get_apikey(username,password)
        if len(key)>0:
            cherrypy.session['api_key']=key
            
            headers=make_headers(username,key)
            pridata=recieve_private_data(headers,unique)
            if pridata==-1:
                raise cherrypy.HTTPRedirect('/login?bad_attempt=1')
            elif pridata==-2:
                #no private data available
                print()
            else:
                data=json.loads(pridata)
                prikey=data['prikeys'][-1]
                prikey=nacl.signing.SigningKey(prikey.encode('utf-8'), encoder=nacl.encoding.HexEncoder)
                cherrypy.session['prikey']=prikey
                
                #send_private_data(headers,username,unique,cherrypy.session['prikey'])
                
                error = authoriseUserLogin(username,password,headers,unique,prikey)
                if error == 0:
                    cherrypy.session['username'] = username
                    ##place to send when logged in
                    worker()
                    raise cherrypy.HTTPRedirect('/')
                elif error==2:
                    raise cherrypy.HTTPRedirect('/serverOffline')
                else:
                    raise cherrypy.HTTPRedirect('/login?bad_attempt=1') 
        else:
            raise cherrypy.HTTPRedirect('/login?bad_attempt=1')

    @cherrypy.expose
    def signout(self):
        global t
        global user
        """Logs the current user out, expires their session"""
        username = cherrypy.session.get('username')
        if username is None:
            pass
        else:            
            user=""
            e.set()
            t.join()
            report(headers,generatePublicKey(cherrypy.session['prikey']).encode(encoder=nacl.encoding.HexEncoder).decode('utf-8'),"offline")
            cherrypy.lib.sessions.expire()
        raise cherrypy.HTTPRedirect('/')


###
# Functions only after here
###

def make_headers(username,api_key):
    headers = {
        'X-username': username,
        'X-apikey': api_key,
        'Content-Type': 'application/json; charset=utf-8',
    }
    return headers

def urlSend(url,headers,payload):
    """[takes a url, the relevant header data, and the payload
    and makes a request to the url with the provided headers
    and payload. Returns a JSON object which contains the
    returned response. In the case of an invalid URL request, will
    print the error message and not return anything]
    
    Arguments:
        url {[string]} -- [The URL to send the request to]
        headers {[dict]} -- [The header data]
        payload {[dict]} -- [The payload data]
    
    Returns:
        [JSON]      -- [The requests response]
    """  
    try:
        req = urllib.request.Request(url, data=json.dumps(
        payload).encode('utf-8'), headers=headers)
        response = urllib.request.urlopen(req)
        data = response.read()  # read the received bytes
        # load encoding if possible (default to utf-8)
        encoding = response.info().get_content_charset('utf-8')
        response.close()
        JSON_object = json.loads(data.decode(encoding))
        print(JSON_object)
        return JSON_object
    except urllib.error.HTTPError as error:
        print(error.read())
    
# def loadPrivateKeys():
#     """[This function will load the private key
#         from the specific file path which has been predetermined.
#         If for whatever reason this function would fail it will return
#         an empty string]
#     """
#     #TODO:
#     try:
#         with open("PrivateKey.txt",'rb') as file:
#             data= file.read()
#         return nacl.signing.SigningKey(data, encoder=nacl.encoding.HexEncoder)
#     except:
#         return ""

# def getPublicKeys():
#     """[This function will attempt to get saved 
#         public keys from the login server]
#     """
#     ## TODO:figure out what to do about certificates
#     try:
#         with open("PublicKey.txt",'rb') as file:
#             data= file.read()
#         return nacl.signing.VerifyKey(data, encoder=nacl.encoding.HexEncoder)
#     except:
#         return ""

# def savePrivateKey(privatekey,publickey):
#     """[This function will save the private key that is currently in use
#         returns a false if unsuccessful]
#     """
#     with open("PrivateKey.txt",'wb') as file:
#         file.write(privatekey)
#     with open("PublicKey.txt",'wb') as file:
#         file.write(publickey)
    
#     #TODO:multiple filepaths needed if more than one private key is made
    
    
def generatePrivateKey():
    """[To be used should there not be an existing private key.
        Takes no inputs but return a nacl.signing key]
    """
    #TODO
    # Generate a new random signing key
    return nacl.signing.SigningKey.generate()

def generatePublicKey(signing_key1):
    """[Takes a Signing Key as input and returns a nacl.verify key as the output]
    
    Arguments:
        signing_key1 {[SigningKey]} -- [The signing key used to make the verify key]
    
    Returns:
        [VerifyKey] -- [The VerifyKey for the signing key provided]
    """
    # Obtain the verify key for a given signing key
    return signing_key1.verify_key
    
def ping(headers,pubkey_hex_str,signature_hex_str):
    """[Calls the ping api on the kiwiland login server,returns the
    JSON recieved from the api ping call. Will not check to see if
    the ping was successful]
    
    Arguments:
        headers {[dict]} -- [headers to be sent]
        pubkey_hex_str {[string]} -- [pubkey encoded in hex, decoded in utf-8]
        signature_hex_str {[string]} -- [pubkey_hex_string+username signed by the signing key that made the pubkey]
    
    Returns:
        [JSON] -- [The requests response]
    """
    url = "http://cs302.kiwi.land/api/ping"

    payload = {

        "pubkey": pubkey_hex_str,
        "signature": signature_hex_str

    }
    return urlSend(url,headers,payload)    
    
def addPubkey(pubkey_hex_str,signature_hex_str,headers,username):
    """[Calls the addPubkey endpoint on the kiwiwland login server, with the intention
    of adding the pubkey inputted to the login server under the inputted username]
    
    Arguments:
        pubkey_hex_str {[string]} -- [pubkey encoded in hex, decoded in utf-8]
        signature_hex_str {[string]} -- [pubkey_hex_string+username signed by the signing key that made the pubkey]
        headers {[dict]} -- [headers to be sent]
        username {[string]} -- [the users username]
    """
    url = "http://cs302.kiwi.land/api/add_pubkey"
    payload = {
        "username": username,
        "pubkey": pubkey_hex_str,
        "signature":signature_hex_str
    }
    urlSend(url,headers,payload)
    
def getLoginserverRecord(headers, username, pubkey_hex_str):
    """[Calls the getLoginserverRecord endpoint from the kiwiland] login server
    to retrieve the login server record for a given pubkey. This function will return
    the loginserver_record and NOT the JSON it came as. Errorhandling to be added]

    Arguments:
        headers {[dict]} -- [headers to be sent]
        username {[string]} -- [The users usernam]
        pubkey_hex_str {[string]} -- [pubkey encoded in hex, decoded in utf-8]

    Returns:
        [string] -- [The Loginserver_record for the pubkey provided]
    """
    url = "http://cs302.kiwi.land/api/get_loginserver_record"
    now = str(time.time())
    payload = {
        "username": username,
        "client_time": now,
        "pubkey": pubkey_hex_str
    }
    # TODO add error handling for invalid records/keys
    return urlSend(url, headers, payload)['loginserver_record']

def report(headers, pubkey_hex_str,status="online"):
    """[This function makes the api call report on the kiwiland login server.
    This function will attempt to notify the login server that the inputed pubkey
    is intended for use for messaging. The pubkey should be asscociated with the account
    already]

    Arguments:
        headers {[dict]} -- [headers to be sent]
        pubkey_hex_str {[string]} -- [pubkey encoded in hex, decoded in utf-8]
    """
    url = "http://cs302.kiwi.land/api/report"
    payload = {
        "connection_address": get_ip()+":8000",
        "connection_location": 1,
        "incoming_pubkey": pubkey_hex_str,
        "status":status
    }
    json=urlSend(url, headers, payload)
    print(json)
    return json

def getServerPubkey(headers):
    """[Calls the getServerPubkey endpoint on the kiwiland login server and retrieves the
    pubkey required for private messaging with the login server. This will be returned as
    a NACL.VERIFY KEY not a STRING.]

    Arguments:
        headers {[dict]} -- [headers to be sent]

    Returns:
        [VerifyKey] -- [the login server's public key used to encrypt private messages sent to the login server]
    """
    url = "http://cs302.kiwi.land/api/loginserver_pubkey"
    payload = {}
    pubkey = urlSend(url, headers, payload)["pubkey"]
    return nacl.signing.VerifyKey(pubkey.encode('utf-8'), encoder=nacl.encoding.HexEncoder)
    
def privateMessage(headers,loginserver_record,target_pubkey,target_user,message,privateKey,address):
    """[Sends off a private message]
    
    Arguments:
        headers {[dict]} -- [headers to be sent]
        loginserver_record {[string]} -- [the login server record for the clients private-public key pair]
        target_pubkey {[signingKey]} -- [the pubkey of the recipient]
        target_user {[string]} -- [the username of the recipient]
        message {[string]} -- [the message to be sent]
        privateKey {[verifyKey]} -- [the clients private key]
    
    Returns:
        [boolean] -- [true on sucess, false on failiure]
    """
    #url = "http://cs302.kiwi.land/api/rx_privatemessage"
    #url = "http://192.168.1.208:8000/api/rx_privatemessage"
    #url = "http://127.0.0.1:8000/api/rx_privatemessage"
    url = "http://"+address+"/api/rx_privatemessage"
    #alt login server
    #url = "http://210.54.33.182:80/api/rx_privatemessage"
    if not(target_user =='admin'):
        headers={
            'Content-Type': 'application/json; charset=utf-8',
        }
    now=str(time.time())
    publickey = target_pubkey.to_curve25519_public_key()
    sealed_box = nacl.public.SealedBox(publickey)
    encrypted = sealed_box.encrypt(bytes(message,encoding='utf-8'), encoder=nacl.encoding.HexEncoder)
    message_bytes = bytes(loginserver_record+target_pubkey.encode(encoder=nacl.encoding.HexEncoder).decode('utf-8')+target_user+encrypted.decode('utf-8') + now, encoding='utf-8')

    # Sign a message with the signing key
    signed = privateKey.sign(
        message_bytes, encoder=nacl.encoding.HexEncoder)
    signature_hex_str = signed.signature.decode('utf-8')
    
    payload={
          "loginserver_record": loginserver_record,  
          "target_pubkey": target_pubkey.encode(encoder=nacl.encoding.HexEncoder).decode('utf-8'),  
          "target_username": target_user,  
          "encrypted_message":encrypted.decode('utf-8'),
          "sender_created_at" : now,  
          "signature" : signature_hex_str
    }
    
    if (urlSend(url,headers,payload))['response']=='ok':
        return True
    else:
        return False
  
def publicMessage(headers,message,prikey):
    """[Sends a public message to the login server]
    
    Arguments:
        message {[string]} -- [the message to be sent]
    """
    #global q
    url = "http://cs302.kiwi.land/api/rx_broadcast"
    address_list = "http://127.0.0.1:8000/api/rx_broadcast"
    address_list=list_address(headers)
    """
    q = Queue()#creating the queue
    for i in range(4):#number of threads
        t = threading.Thread(target=worker1)#create thread???
        t.daemon = True  # thread dies when main thread (only non-daemon thread) exits.
        t.start()#start thread
"""
    #address_list=["172.23.103.37:1234"]
    for i in address_list:
        url="http://"+i+"/api/rx_broadcast"
        try:
            ping_check(headers,i)
        except urllib.error.URLError:
            print()
        signing_key1=prikey
            
        #seems to always make the same public key, no salt i guess
        verify_key1=generatePublicKey(signing_key1)
        
        # Serialize the verify key to send it to a third party
        pubkey_hex = verify_key1.encode(encoder=nacl.encoding.HexEncoder)
        pubkey_hex_str = pubkey_hex.decode('utf-8')
        
        now = str(time.time())
        username=cherrypy.session['username']
        Login_server_record_str=getLoginserverRecord(headers,username,pubkey_hex_str)
        

        # Sign a message with the signing key
        message_bytes = bytes(Login_server_record_str+message+now, encoding='utf-8')
        signed = signing_key1.sign( message_bytes, encoder=nacl.encoding.HexEncoder)
        signature_hex_str = signed.signature.decode('utf-8')
            
        payload = {
            "loginserver_record":Login_server_record_str,
            "message": message,
            "sender_created_at": now,
            "signature": signature_hex_str
                # STUDENT TO COMPLETE THIS...
        }
        
        if not(i == "210.54.33.182:80"):
            try:
                blank_headers={
                    'Content-Type': 'application/json; charset=utf-8',
                }
                "q.put([url,blank_headers,payload])"
                urlSend(url,blank_headers,payload)
            except:
                print()
        else:
            urlSend(url,headers,payload)
    q.join()
"""
def worker1():
    global q
    while True:
        item = q.get()#get a thing from a queue
        try:
            urlSend(item[0],item[1],item[2])#run the do_work def with the item in the queue
        except:
            print()
        q.task_done()#complete the task
"""

    
def getUsers(headers):   
    """[gets a list of users from the login server]
    
    Returns:
        [JSON] -- [a dict containing a single element 'users' which contains a list containing each users data in a dict]
    """
    url="http://cs302.kiwi.land/api/list_users" 
    payload=""
    data= urlSend(url,headers,payload)
    print(data)
    return data
    
def send_private_data(headers,username,unique,prikey): 
    now=str(time.time())
    prikeys=[]
    prikeys.append(prikey.encode(encoder=nacl.encoding.HexEncoder).decode('utf-8'))
    pubkey_hex_str=generatePublicKey(prikey).encode(encoder=nacl.encoding.HexEncoder).decode('utf-8')
    url="http://cs302.kiwi.land/api/add_privatedata" 
    record=getLoginserverRecord(headers,username,pubkey_hex_str)
                                            
    pridata={   
        "prikeys": prikeys,
        "blocked_pubkeys": [],
        "blocked_usernames": [],
        "blocked_words": [],
        "blocked_message_signatures": [],
        "favourite_message_signatures": [],
        "friends_usernames": []
    }
    pridata=(json.dumps(pridata).encode('utf-8'))
    
    key=nacl.pwhash.argon2i.kdf(32,unique.encode('utf-8'),(unique*16).encode('utf-8')[:16],opslimit=nacl.pwhash.argon2i.OPSLIMIT_SENSITIVE,memlimit=nacl.pwhash.argon2i.MEMLIMIT_SENSITIVE,encoder=nacl.encoding.RawEncoder)
    box = nacl.secret.SecretBox(key)
    
    nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)

    encrypted = (base64.b64encode(box.encrypt(pridata, nonce))).decode('utf-8')
    
    message_bytes = bytes(encrypted + record+now, encoding='utf-8')
    signing_key1=prikey
    # Sign a message with the signing key
    signed = signing_key1.sign(
        message_bytes, encoder=nacl.encoding.HexEncoder)
    signature_hex_str = signed.signature.decode('utf-8')
    
    payload={  
            "privatedata": encrypted,
            "loginserver_record": record,
            "client_saved_at": now,
            "signature": signature_hex_str
    }
    print(urlSend(url,headers,payload))

def recieve_private_data(headers,unique):
    if len(unique)==0:
        return ""
    url="http://cs302.kiwi.land/api/get_privatedata" 
    payload={}
    JSON=urlSend(url,headers,payload)
    if JSON['response']=='error':
        return -1
    elif JSON['response']=='no privatedata available':
        return -2
    key=nacl.pwhash.argon2i.kdf(32,unique.encode('utf-8'),(unique*16).encode('utf-8')[:16],opslimit=nacl.pwhash.argon2i.OPSLIMIT_SENSITIVE,memlimit=nacl.pwhash.argon2i.MEMLIMIT_SENSITIVE,encoder=nacl.encoding.RawEncoder)
    box = nacl.secret.SecretBox(key)
    try:
        plaintext = box.decrypt(JSON['privatedata'],encoder=nacl.encoding.Base64Encoder)
        data=(plaintext).decode('utf-8')
    except nacl.exceptions.CryptoError:
        data=-1
    return data
    
def list_address(headers):
    users=getUsers(headers)['users']
    output=[]
    for i in users:
        output.append(i['connection_address'])
    return output 

def check_pubkey(headers,pub_key):
    url="http://cs302.kiwi.land/api/check_pubkey?pubkey="+pub_key 
    payload={}
    return urlSend(url,headers,payload)

def check_messages(headers):
    address=list_address(headers)
    temp=[]
    for i in address:
        if not (address == get_ip()+":8000"):
            url="http://"+i+"/api/checkmessages?since=0" 
            payload={}
            try:
                JSON=urlSend(url,headers,payload)
                try:
                    for i in JSON:
                        temp.append(i)
                except TypeError:
                    continue
                try:
                    if JSON['response']=='ok':
                        break
                except KeyError:
                    continue
            except:
                print("ERROR\n")
                continue

        
    temp = list( dict.fromkeys(temp) ) 
    print(temp)
    
def ping_check(headers,address):
    url="http://"+address+"/api/ping_check"
    payload={  
            "my_time": str(time.time()),
            "connection_address": get_ip(),  
            "connection_location": 2}
    urlSend(url,headers,payload)
    
def refresh_user():
    global headers
    global pubkey_hex_str
    global e
    while not e.wait(timeout=180):
        report(headers,pubkey_hex_str)
    
def worker():
    global t
    global e
    e.clear()
    t=threading.Thread(target=refresh_user)
    t.daemon=True
    t.start()
    
def get_ip():
    #ip address extraction
    ip_command =check_output(["hostname","-I"])
    ip_string = ip_command.decode('utf-8')
    ip_add = ip_string[:len(ip_string)-2]
    if ip_add.find(' '):
        ip_add=ip_add.split(' ')[0]
    return ip_add
    
def get_apikey(username,password):
    url="http://cs302.kiwi.land/api/load_new_apikey" 
    credentials = ('%s:%s' % (username, password))
    b64_credentials = base64.b64encode(credentials.encode('ascii'))
    headers = {
        'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
        'Content-Type': 'application/json; charset=utf-8',
    }
    payload={}
    JSON=urlSend(url,headers,payload)
    try:
        key=JSON['api_key']
    except TypeError:
        return ""
    return key
    
def authoriseUserLogin(username,password,header,unique,prikey):
    global headers
    global pubkey_hex_str
    print(header)
    headers=header
    print("Log on attempt from {0}:{1}".format(username, password))
    try:
        
        signing_key1=prikey
        
        #seems to always make the same public key, no salt i guess
        verify_key1=generatePublicKey(signing_key1)
        #signing_key = nacl.signing.SigningKey(hex_key, encoder=nacl.encoding.HexEncoder)
        
        # Serialize the verify key to send it to a third party
        pubkey_hex = verify_key1.encode(encoder=nacl.encoding.HexEncoder)
        pubkey_hex_str = pubkey_hex.decode('utf-8')
        message_bytes = bytes(pubkey_hex_str + username, encoding='utf-8')

        # Sign a message with the signing key
        signed = signing_key1.sign(
            message_bytes, encoder=nacl.encoding.HexEncoder)
        signature_hex_str = signed.signature.decode('utf-8')
        
        ping(headers,pubkey_hex_str,signature_hex_str)
        #addPubkey(pubkey_hex_str,signature_hex_str,headers,username)'
        #check_messages(headers)
        if report(headers,pubkey_hex_str)['response'] == 'error':
            return 1
        return 0
    except urllib.error.HTTPError as error:
        print(error.read())
        return 1
    except urllib.error.URLError as error:
        return 2