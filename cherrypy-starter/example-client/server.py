import base64
import json
import time
import urllib.request

import cherrypy
from asn1crypto.keys import PrivateKeyAlgorithm
from Crypto.PublicKey.pubkey import pubkey
import nacl.encoding
import nacl.signing
import nacl.utils
from nacl.public import PrivateKey, Box

startHTML = """
<html>
    <head>
        <title>CS302 example</title> 
        <link rel="stylesheet" type="text/css" href="default.css">
    </head>
    <body>
"""
DefaultHeader="""
            <div id="navbar">
            <a href="/">Home</a>
            <a href="/login">Login</a>
            <a href="/message">Message</a>
            </div><script src="default.js"></script>
            <div class="content">"""
LoginHeader="""
            <div id="navbar">
            <a href="/">Home</a>
            <a href="/signout">Log Out</a>
            <a href="/message">Message</a>
            </div><script src="default.js"></script>
            <div class="content">"""
endHTML="</div></body></html>"
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
    def index(self):
        Page=startHTML
        try:
            user=cherrypy.session['username']
            Page += LoginHeader
            Page +=  "<p><h3>Welcome! This is a test website for COMPSYS302!</h3><br/>"
            Page += "Hello " + user + "!<br/>"
            Page += "Here is some bonus text because you've logged in! HERE IS SOME EXTRA TEXT AGAIN! <a href='/signout'>Sign out</a>"
        except KeyError:
            Page += DefaultHeader
            Page +=  "<p><div id='messageHeading'><h3>Welcome! This is a test website for COMPSYS302! This is also a message heading, normally usernames will be here</h3></br><div id='message'><p>heres some text to serve as the messages contents</p></div></div><br/>"
            Page += "Click here to <a href='login'>login</a>, alternatively use the button at the top."
        Page += "<br/><br/><br/><br/><br/><br/><br/><br/><br/><br/><br/><br/><br/><br/><br/><br/><br/><br/><br/><br/><br/><br/><br/><br/><br/><br/><br/><br/><br/><br/><br/><br/><br/><br/><br/><br/><br/><br/><br/>Some text down here to show scrolling</p>"
        Page += endHTML
        return Page
    
    @cherrypy.expose
    def home(self):
        Page = startHTML + "Hi, this is a super secret extra webpage<br/>"

        try:
            Page += "Hello " + cherrypy.session['username'] + "!<br/>"
            Page += "I see that you have already logged in "
        except KeyError:  # There is no username
            Page += "I see that you have not yet logged in."
        Page += "<a href='/'>Press to go back</a>"
        Page += endHTML
        return Page
    
    @cherrypy.expose
    def message(self):
        Page = startHTML
        Page += '<form autocomplete="off" action="/publicMessage" method="post" enctype="multipart/form-data">'
        Page += 'Message: <textarea palceholder="Type your message here" name="message" rows="10" cols="30" size="50" type="text"> </textarea><br/>'
        Page += '<input type="submit" value="Submit"/></form>'
        Page += "</b></test>"
        Page += endHTML
        return Page
    
    
    @cherrypy.expose
    def publicMessage(self,message=""):
        print(message)
        raise cherrypy.HTTPRedirect('/')
    
    @cherrypy.expose
    def serverOffline(self):
        Page = startHTML
        Page += "The login server is unavailable or down for maintainence, please try again later"
        Page += "<br> Sorry for the inconvenience, once we have been notified we will contact the server owner<br/>"
        Page += endHTML
        return Page
    
    @cherrypy.expose
    def login(self, bad_attempt=0):
        Page = startHTML+DefaultHeader
        if bad_attempt != 0:
            Page += "<font color='red'>Invalid username/password!</font>"
        Page += "<h1>Sign in to your account</h1>"
        Page += "<test><b>"
        Page += '<form action="/signin" method="post" enctype="multipart/form-data">'
        Page += 'Username: <input size="50" type="text" name="username"/><br/>'
        Page += 'Password: <input size="50" type="text" name="password"/><br/>'
        Page += '<input type="submit" value="Login"/></form>'
        Page += "</b></test>"
        Page += endHTML
        return Page

    @cherrypy.expose
    def sum(self, a=0, b=0):  # All inputs are strings by default
        output = int(a)+int(b)
        return str(output)

    # LOGGING IN AND OUT
    @cherrypy.expose
    def signin(self, username=None, password=None):
        """Check their name and password and send them either to the main page, or back to the main login screen."""
        error = authoriseUserLogin(username, password)
        if error == 0:
            cherrypy.session['username'] = username
            ##place to send when logged in
            raise cherrypy.HTTPRedirect('/')
        elif error==2:
            raise cherrypy.HTTPRedirect('/serverOffline')
        else:
            raise cherrypy.HTTPRedirect('/login?bad_attempt=1')

    @cherrypy.expose
    def signout(self):
        """Logs the current user out, expires their session"""
        username = cherrypy.session.get('username')
        if username is None:
            pass
        else:
            cherrypy.lib.sessions.expire()
        raise cherrypy.HTTPRedirect('/')


###
# Functions only after here
###
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
        
def checkPrivateKey():
    """[This function will check for the private key
    text file and return true if it exists and false if it
    does not]
    """
    #TODO:

def loadPrivateKeys():
    """[This function will load the private key
        from the specific file path which has been predetermined.
        If for whatever reason this function would fail it will return
        an empty string]
    """
    #TODO:
    try:
        with open("PrivateKey.txt",'rb') as file:
            data= file.read()
        return nacl.signing.SigningKey(data, encoder=nacl.encoding.HexEncoder)
    except:
        return ""

def getPublicKeys():
    """[This function will attempt to get saved 
        public keys from the login server]
    """
    ## TODO:figure out what to do about certificates
    try:
        with open("PublicKey.txt",'rb') as file:
            data= file.read()
        return nacl.signing.SigningKey(data, encoder=nacl.encoding.HexEncoder)
    except:
        return ""

def savePrivateKey(privatekey,publickey):
    """[This function will save the private key that is currently in use
        returns a false if unsuccessful]
    """
    with open("PrivateKey.txt",'wb') as file:
        file.write(privatekey)
    with open("PublicKey.txt",'wb') as file:
        file.write(publickey)
    
    #TODO:multiple filepaths needed if more than one private key is made
    
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
    JSON recieved from the api ping call]
    
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
    
def getLoginserverRecord(headers,username,pubkey_hex_str):
    url = "http://cs302.kiwi.land/api/get_loginserver_record"
    now=str(time.time())
    payload = {
        "username": username,
        "client_time": now,
        "pubkey":pubkey_hex_str
    }
    return urlSend(url,headers,payload)['loginserver_record']
    
def report(headers,pubkey_hex_str):
    url = "http://cs302.kiwi.land/api/report"
    payload={
        "connection_address": "127.0.0.1:8000",  
        "connection_location": 1,
        "incoming_pubkey": pubkey_hex_str
    }
    urlSend(url,headers,payload)
    
def getServerPubkey(headers):
    url="http://cs302.kiwi.land/api/loginserver_pubkey"
    payload={}
    pubkey=urlSend(url,headers,payload)["pubkey"]
    return nacl.signing.VerifyKey(pubkey.encode('utf-8'), encoder=nacl.encoding.HexEncoder)
    
def privateMessage(headers,loginserver_record,target_pubkey,target_user,message,username,privateKey):
    url = "http://cs302.kiwi.land/api/rx_privatemessage"
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
    urlSend(url,headers,payload)
    
def authoriseUserLogin(username, password):
    print("Log on attempt from {0}:{1}".format(username, password))
    try:
        signing_key1=loadPrivateKeys()
        
        #seems to always make the same public key, no salt i guess
        verify_key1=generatePublicKey(signing_key1)
        #signing_key = nacl.signing.SigningKey(hex_key, encoder=nacl.encoding.HexEncoder)
        savePrivateKey(signing_key1.encode(encoder=nacl.encoding.HexEncoder),verify_key1.encode(encoder=nacl.encoding.HexEncoder))
        
        
        # Serialize the verify key to send it to a third party
        pubkey_hex = verify_key1.encode(encoder=nacl.encoding.HexEncoder)
        pubkey_hex_str = pubkey_hex.decode('utf-8')
        message_bytes = bytes(pubkey_hex_str + username, encoding='utf-8')

        # Sign a message with the signing key
        signed = signing_key1.sign(
            message_bytes, encoder=nacl.encoding.HexEncoder)
        signature_hex_str = signed.signature.decode('utf-8')
        
        credentials = ('%s:%s' % (username, password))

        b64_credentials = base64.b64encode(credentials.encode('ascii'))
        headers = {
            'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
            'Content-Type': 'application/json; charset=utf-8',
        }
        ping(headers,pubkey_hex_str,signature_hex_str)
        #addPubkey(pubkey_hex_str,signature_hex_str,headers,username)'
        report(headers,pubkey_hex_str)
        """
        loginserver_record=getLoginserverRecord(headers,username,pubkey_hex_str)
        target_pubkey=getServerPubkey(headers)
        message="This is a test"
        target_user="admin"
        
        privateMessage(headers,loginserver_record,target_pubkey,target_user,message,username,signing_key1)
        """
        #commented out to not send a message to the login server
        
        
        
        
        """
        url = "http://cs302.kiwi.land/api/rx_broadcast"
        now = str(time.time())
        message = "Hello world!"
        message_bytes = bytes(Login_server_record_str+message+now, encoding='utf-8')


        # Sign a message with the signing key
        signed = signing_key1.sign(
            message_bytes, encoder=nacl.encoding.HexEncoder)
        signature_hex_str = signed.signature.decode('utf-8')
        
        payload = {
            "loginserver_record":Login_server_record_str,
            "message": message,
            "sender_created_at": now,
            "signature": signature_hex_str
            # STUDENT TO COMPLETE THIS...
        }
        
        req = urllib.request.Request(url, data=json.dumps(
            payload).encode('utf-8'), headers=headers)
        response = urllib.request.urlopen(req)
        data = response.read()  # read the received bytes
        # load encoding if possible (default to utf-8)
        encoding = response.info().get_content_charset('utf-8')
        response.close()
        JSON_object = json.loads(data.decode(encoding))
        print(JSON_object)
        """
        return 0
    except urllib.error.HTTPError as error:
        print(error.read())
        exit()
        return 1
    except urllib.error.URLError as error:
        return 2