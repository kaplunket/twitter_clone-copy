import ast
import base64
import json
import sqlite3
import threading
import time
import urllib.request
from collections import OrderedDict
from email.header import make_header
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
from nacl.public import Box, PrivateKey

statuses={}
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
            <a href="/">Public</a>
            <a href="/private_messages">PM's</a>
            <a href="/signout">Log Out</a>
            <a href="/message">Message</a>
            <a href="/users">Users</a>
            <a href="/account">Account</a>
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
        saveTime()
        try:
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
            if JSON['loginserver_record']==data['loginserver_record']:
                verifykey=nacl.signing.VerifyKey(pubkey.encode('utf-8'), encoder=nacl.encoding.HexEncoder)
                decoded_sig=(data['loginserver_record']+message+data['sender_created_at']).encode('utf-8')
                signature=data['signature'].encode('utf-8')
                #verifykey.verify(decoded_sig,signature=(signature),encoder=nacl.encoding.HexEncoder)
                
                conn = sqlite3.connect("my.db")
                c = conn.cursor() 
                
                c.execute("""SELECT COUNT (id)  FROM pubmessages;""")
                result=c.fetchone()
                
                c.execute("INSERT INTO pubmessages (id,message,recieved_at,sender)VALUES (?,?,?,?)",(str(int(result[0])+1), str(data),str(time.time()),data['loginserver_record'].split(',')[0],))
                conn.commit()
                    
                conn.close()

                payload={ "response": "ok"}
            else:
                payload={ "response": "error",'message':'Invalid loginserver_record'}
            return payload
        except KeyError:
            payload={"response": "error",'message':'Missing parameters'}
            return payload
        
    @cherrypy.expose
    @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    def rx_privatemessage(self,data="",headers=""):
        saveTime()
        try:
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
        except KeyError:
            payload={"response": "error",'message':'Missing parameters'}
            return payload
        
    @cherrypy.expose
    @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    def checkmessages(self,since="0"):
        try:
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
        except ValueError:
            payload={"response": "error",'message':'Invalid data type'}
        return payload
        
    @cherrypy.expose
    @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    def rx_groupmessage(self):
        payload={ "response": "error", "message":"This server does not implement this endpoint"}
        return payload
        
    @cherrypy.expose
    @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    def rx_groupinvite(self):
        payload={ "response": "error", "message":"This server does not implement this endpoint"}
        return payload

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
            
            favourited=[]
            for row in rows:
                temp=""
                message=ast.literal_eval(row[1])['message']
                if(message.find("!Meta:")!=-1):
                    temp=message.split('!Meta:')[1]
                    if temp.find('favourite_broadcast:[')!=-1:
                        favourited.append(temp.split('favourite_broadcast:[')[1][:-1])
                    elif temp.find('block_broadcast:[')!=-1:
                        print()
                    elif temp.find('block_pubkey:[')!=-1:
                        print()
                    elif temp.find('block_username:[')!=-1:
                        print()
            for row in rows:
                temp=""
                message=ast.literal_eval(row[1])['message']
                user = ast.literal_eval(row[1])['loginserver_record'].split(",")[0]
                signature=ast.literal_eval(row[1])['signature']
                if(message.find("!Meta:")==-1):
                    
                    cleaned_text=remove_HTML_tags(message)
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
                    likes=0
                    for i in favourited:
                        if i==signature:
                            likes=likes+1
                    block=False
                    for i in cherrypy.session['blocked_usernames']:
                        if user==i:
                            block=True
                    for i in cherrypy.session['blocked_words']:
                        if message.find(i)!=-1:
                            block=True
                    for i in cherrypy.session['blocked_pubkeys']:
                        if pubkey==i:
                            block=True
                    for i in cherrypy.session['blocked_message_signatures']:
                        if signature==i:
                            block=True
                    if block:
                        continue    
                        
                                
                    if len(search)>0:
                        if not(user.find(search)==-1 and message.find(search)==-1):
                            temp +=  "<p><div id='messageHeading'><h3>"+user+"</h3>"
                            temp += "</br><div id='message'><p class='c'word-break: break-all;>"+message+"</p></div>Likes:"+str(likes)        
                            temp += '<form autocomplete="off" action="/public" method="post" enctype="multipart/form-data">'
                            temp += '<input type="hidden" name="message" value="!Meta:favourite_broadcast:['+signature+']' + ' "/>'
                            temp += '<input type="submit" value="Like"/></form>'
                            array.append(temp)
                    else:
                        temp +=  "<p><div id='messageHeading'><h3>"+user+"</h3>"
                        temp += "</br><div id='message'><p class='c'word-break: break-all;>"+message+"</p></div>Likes:"+str(likes)                            
                        temp += '<form autocomplete="off" action="/public" method="post" enctype="multipart/form-data">'
                        temp += '<input type="hidden" name="message" value="!Meta:favourite_broadcast:['+signature+']' + '"/>'
                        temp += '<input type="submit" value="Like"/></form>'
                        array.append(temp)


            for i in reversed(array):
                Page += i +"</div><br/>"
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
                signature=ast.literal_eval(row[1])['signature']
                try:
                    VF=cherrypy.session['prikey']
                    PK = VF.to_curve25519_private_key()
                    box = nacl.public.SealedBox(PK)
                    message=box.decrypt(message.encode('utf-8'), encoder=nacl.encoding.HexEncoder).decode('utf-8')
                    
                    if(message.find("!Meta:")==-1):
                        
                        cleaned_text=remove_HTML_tags(message)
                                
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
                            
                        block=False
                        for i in cherrypy.session['blocked_usernames']:
                            if user==i:
                                block=True
                        for i in cherrypy.session['blocked_words']:
                            if message.find(i)!=-1:
                                block=True
                        for i in cherrypy.session['blocked_pubkeys']:
                            if pubkey==i:
                                block=True
                        for i in cherrypy.session['blocked_message_signatures']:
                            if signature==i:
                                block=True
                        if block:
                            continue    
                            
                        if len(search)>0:
                            if not(user.find(search)==-1 and message.find(search)==-1):
                                temp +=  "<p><div id='messageHeading'><h3>"+user+"</h3>"
                                temp += "</br><div id='message'><p class='c' word-break: break-all;>"+message+"</p></div>"
                                temp += "<a href=p2p?user="+ user+"&pubkey="+ pubkey+"&address=*>Reply</a>"+"</div><br/>"
                                array.append(temp)
                        else:
                            temp +=  "<p><div id='messageHeading'><h3>"+user+"</h3>"
                            temp += "</br><div id='message'><p class='c'word-break: break-all;>"+message+"</p></div>"
                            temp += "<a href=p2p?user="+ user+"&pubkey="+ pubkey+"&address=*>Reply</a>"+"</div><br/>"
                            array.append(temp)
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
        Page += 'Message: <textarea placeholder="Type your message here" name="message" rows="3" cols="50" size="50" type="text"> </textarea><br/>'
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
                Page += 'Message: <textarea placeholder="Type your message here" name="message" rows="3" cols="50" size="50" type="text"> </textarea><br/>'
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
    def account(self):
        try:
            cherrypy.session['username']
        except KeyError:
            raise cherrypy.HTTPRedirect('/')
        header=make_headers(cherrypy.session['username'],cherrypy.session['api_key'])
        data=json.loads(recieve_private_data(header,cherrypy.session['unique']))
        cherrypy.session['keylist']=data['prikeys']
        for i in range(0,len(cherrypy.session['keylist'])):
            cherrypy.session['keylist'][i]=nacl.signing.SigningKey(bytes(cherrypy.session['keylist'][i], encoding='utf-8'),encoder=nacl.encoding.HexEncoder)
                
        Page=startHTML+LoginHeader
        Page+="<h1>Account: "+cherrypy.session['username']+"</h1>"
        Page+="Status:"
        Page+="<form class='status' action='/change_status?status=online' method='post' enctype='multipart/form-data'>"
        Page += '<input type="submit" value="Online"/></form>'
        Page+="<form class='status' action='/change_status?status=busy' method='post' enctype='multipart/form-data'>"
        Page += '<input type="submit" value="Busy"/></form>'
        Page+="<form class='status' action='/change_status?status=away' method='post' enctype='multipart/form-data'>"
        Page += '<input type="submit" value="Away"/></form>'
        Page+="<form class='status' action='/change_status?status=offline' method='post' enctype='multipart/form-data'>"
        Page += '<input type="submit" value="Offline"/></form>'
        Page+="<br/>Private Keys:<ul>"
        for i in cherrypy.session['keylist']:
            Page+="<li>"+i.encode(encoder=nacl.encoding.HexEncoder).decode('utf-8')+"</li>"
        Page+="</ul>"
        Page += '<form action="/clear_blocked_data" method="post" enctype="multipart/form-data">'
        Page += '<input type="submit" value="CLEAR BLOCK DATA"/></form>'
        Page+="Blocked username:<ul>"
        for i in cherrypy.session['blocked_usernames']:
            Page+="<li>"+i+"</li>"
        Page+="</ul>"
        Page+="Block username:"
        Page += '<form action="/add_blocked_username" method="post" enctype="multipart/form-data">'
        Page += 'New: <input id="bar" size="20" type="text" name="block"/><br/>'
        Page += '<input type="submit" value="Submit"/></form>'
        Page+="Blocked pubkeys:<ul>"
        for i in cherrypy.session['blocked_pubkeys']:
            Page+="<li>"+i+"</li>"
        Page+="</ul>"
        Page+="Block pubkey:"
        Page += '<form action="/add_blocked_username" method="post" enctype="multipart/form-data">'
        Page += 'New: <input id="bar" size="20" type="text" name="pubkey"/><br/>'
        Page += '<input type="submit" value="Submit"/></form>'
        Page+="Blocked words:<ul>"
        for i in cherrypy.session['blocked_words']:
            Page+="<li>"+i+"</li>"
        Page+="</ul>"
        Page+="Block words:"
        Page += '<form action="/add_blocked_username" method="post" enctype="multipart/form-data">'
        Page += 'New: <input id="bar" size="20" type="text" name="words"/><br/>'
        Page += '<input type="submit" value="Submit"/></form>'
        Page+="Blocked signatures:<ul>"
        for i in cherrypy.session['blocked_message_signatures']:
            Page+="<li>"+i+"</li>"
        Page+="</ul>"
        Page+="Block signature:"
        Page += '<form action="/add_blocked_username" method="post" enctype="multipart/form-data">'
        Page += 'New: <input id="bar" size="20" type="text" name="sign"/><br/>'
        Page += '<input type="submit" value="Submit"/></form>'
        Page+="Change encryption password:"
        Page += '<form action="/change_encrypt" method="post" enctype="multipart/form-data">'
        Page += 'New: <input id="bar" size="20" type="text" name="new"/><br/>'
        Page += '<input type="submit" value="Submit"/></form>'
        Page += "Clear private data:"
        Page += '<form action="/" method="post" enctype="multipart/form-data">'
        Page += '<input type="submit" value="CLEAR"/></form>'
        Page+= endHTML
        return Page
    
    @cherrypy.expose
    def add_blocked_username(self,block="",pubkey="",sign="",words=""):
        try:
            cherrypy.session['username']
            if len(block)>0:
                cherrypy.session['blocked_usernames'].append(block)
            if len(pubkey)>0:
                cherrypy.session['blocked_pubkeys'].append(pubkey)
            if len(sign)>0:
                cherrypy.session['blocked_message_signatures'].append(sign)
            if len(words)>0:
                cherrypy.session['blocked_words'].append(words)
            send_private_data(headers,cherrypy.session['username'],cherrypy.session['unique'],cherrypy.session['keylist'],cherrypy.session['blocked_pubkeys'],cherrypy.session['blocked_usernames'],cherrypy.session['blocked_words'],cherrypy.session['blocked_message_signatures'],cherrypy.session['favourite_message_signatures'],cherrypy.session['friends_usernames'])
            raise cherrypy.HTTPRedirect('/account')
        except KeyError:
            raise cherrypy.HTTPRedirect('/')

    @cherrypy.expose
    def clear_blocked_data(self):
        send_private_data(headers,cherrypy.session['username'],cherrypy.session['unique'],cherrypy.session['keylist'],[],[],[],[],cherrypy.session['favourite_message_signatures'],cherrypy.session['friends_usernames'])
        cherrypy.session['blocked_pubkeys']=[]
        cherrypy.session['blocked_usernames']=[]
        cherrypy.session['blocked_words']=[]
        cherrypy.session['blocked_message_signatures']=[]
        cherrypy.session['favourite_message_signatures']=[]
        cherrypy.session['friends_usernames']=[]
        raise cherrypy.HTTPRedirect('/account')
        
    @cherrypy.expose
    def change_encrypt(self,new=""):
        if new=="":
            raise cherrypy.HTTPRedirect('/account')
        
        make_headers(cherrypy.session['username'],cherrypy.session['api_key'])
        send_private_data(headers,cherrypy.session['username'],new,cherrypy.session['keylist'],cherrypy.session['blocked_pubkeys'],cherrypy.session['blocked_usernames'],cherrypy.session['blocked_words'],cherrypy.session['blocked_message_signatures'],cherrypy.session['favourite_message_signatures'],cherrypy.session['friends_usernames'])
        cherrypy.session['unique']=new
        raise cherrypy.HTTPRedirect('/account')
    
    @cherrypy.expose
    def change_status(self,status="online"):
        global statuses
        statuses[cherrypy.session['username']]=[statuses[cherrypy.session['username']][0],status]
        #headers = make_header( cherrypy.session['username'] , statuses[cherrypy.session['username']][0] )
        #pubkey_hex_str=bytes(generatePublicKey(cherrypy.session['prikey']),encoding=nacl.encoding.HexEncoder).decode('utf-8')
        #report(headers,pubkey_hex_str,status)
        raise cherrypy.HTTPRedirect('/account')
    
    @cherrypy.expose
    def serverOffline(self):
        try:
            cherrypy.session['username']
            Page = startHTML+LoginHeader
        except KeyError:
            Page = startHTML+DefaultHeader
        Page += "The login server is unavailable or down for maintainence, please try again later"
        Page += "<br> Sorry for the inconvenience, once we have been notified we will contact the server owner<br/>"
        Page += endHTML
        return Page
    
    @cherrypy.expose
    def login(self, bad_attempt=0,data_created=0):
        Page = startHTML+DefaultHeader+"<div id='login'>"
        Page += "<h1>Sign in to your account</h1>"
        Page += "<test><b>"
        Page += '<form action="/signin" method="post" enctype="multipart/form-data">'
        if bad_attempt != 0:
            Page += "<font color='red'>Invalid username/password!</font><br/>"
        if data_created != 0:
            Page += "<font color='green'>Private data created!</font><br/>"
        Page += 'Username: <input id="bar" size="50" type="text" name="username"/><br/>'
        Page += 'Password: <input id="bar" size="50" type="text" name="password"/><br/>'
        Page += 'Encryption: <input id="bar" size="50" type="text" name="unique"/><br/>'
        Page += '<input type="submit" value="Login"/></form>'
        Page += "</b></test></div>"
        Page += endHTML
        return Page
    
    # LOGGING IN AND OUT
    @cherrypy.expose
    def signin(self, username=None, password=None,unique=None):
        global statuses
        """Check their name and password and send them either to the main page, or back to the main login screen."""
        key=get_apikey(username,password)
        if len(key)>0:
            cherrypy.session['api_key']=key
            
            headers=make_headers(username,key)
            pridata=recieve_private_data(headers,unique)
            if pridata==-1:
                raise cherrypy.HTTPRedirect('/login?bad_attempt=1')
            elif pridata==-2:
                pri_key=generatePrivateKey()
                pubkey_hex_str=(generatePublicKey(pri_key).encode(encoder=nacl.encoding.HexEncoder).decode('utf-8'))
                
                message_bytes = bytes(pubkey_hex_str+username, encoding='utf-8')

                # Sign a message with the signing key
                signed = pri_key.sign(
                    message_bytes, encoder=nacl.encoding.HexEncoder)
                signature_hex_str = signed.signature.decode('utf-8')
                
                
                addPubkey(pubkey_hex_str,signature_hex_str,headers,username)
                
                report(headers,pubkey_hex_str)
                
                send_private_data(headers,username,unique,cherrypy.session['keylist'],cherrypy.session['blocked_pubkeys'],cherrypy.session['blocked_usernames'],cherrypy.session['blocked_words'],cherrypy.session['blocked_message_signatures'],cherrypy.session['favourite_message_signatures'],cherrypy.session['friends_usernames'])
                raise cherrypy.HTTPRedirect('/login?data_created=1') 
                
            else:
                data=json.loads(pridata)
                if (len(data['prikeys']))==0:
                    pri_key=generatePrivateKey()
                    pubkey_hex_str=(generatePublicKey(pri_key).encode(encoder=nacl.encoding.HexEncoder).decode('utf-8'))
                    
                    message_bytes = bytes(pubkey_hex_str+username, encoding='utf-8')

                    # Sign a message with the signing key
                    signed = pri_key.sign(
                        message_bytes, encoder=nacl.encoding.HexEncoder)
                    signature_hex_str = signed.signature.decode('utf-8')
                    
                    addPubkey(pubkey_hex_str,signature_hex_str,headers,username)
                    report(headers,pubkey_hex_str)
                    
                    send_private_data(headers,username,unique,cherrypy.session['keylist'],[],[],[],[],[],[])
                    raise cherrypy.HTTPRedirect('/login?data_created=1') 
                    
                prikey=data['prikeys'][-1]
                prikey=nacl.signing.SigningKey(prikey.encode('utf-8'), encoder=nacl.encoding.HexEncoder)
                cherrypy.session['keylist']=data['prikeys']
                cherrypy.session['blocked_pubkeys']=data['blocked_pubkeys']
                cherrypy.session['blocked_usernames']=data['blocked_usernames']
                cherrypy.session['blocked_words']=data['blocked_words']
                cherrypy.session['blocked_message_signatures']=data['blocked_message_signatures']
                cherrypy.session['favourite_message_signatures']=data['favourite_message_signatures']
                cherrypy.session['friends_usernames']=data['friends_usernames']
                
                cherrypy.session['prikey']=prikey
                cherrypy.session['unique']=unique
                
                for i in range(0,len(cherrypy.session['keylist'])):
                    cherrypy.session['keylist'][i]=nacl.signing.SigningKey(bytes(cherrypy.session['keylist'][i], encoding='utf-8'),encoder=nacl.encoding.HexEncoder)
                
                send_private_data(headers,username,unique,[cherrypy.session['prikey']],cherrypy.session['blocked_pubkeys'],cherrypy.session['blocked_usernames'],cherrypy.session['blocked_words'],cherrypy.session['blocked_message_signatures'],cherrypy.session['favourite_message_signatures'],cherrypy.session['friends_usernames'])
                
                error = authoriseUserLogin(username,password,headers,unique,prikey)
                if error == 0:
                    cherrypy.session['username'] = username
                    ##place to send when logged in
                    statuses[username]=[key,"online"]
                    cherrypy.session['thread']=worker()
                    raise cherrypy.HTTPRedirect('/')
                elif error==2:
                    raise cherrypy.HTTPRedirect('/serverOffline')
                else:
                    raise cherrypy.HTTPRedirect('/login?bad_attempt=1') 
        else:
            raise cherrypy.HTTPRedirect('/login?bad_attempt=1')

    @cherrypy.expose
    def signout(self):
        global user
        global statuses
        """Logs the current user out, expires their session"""
        username = cherrypy.session.get('username')
        if username is None:
            pass
        else:         
            t=cherrypy.session['thread']   
            user=""
            e.set()
            t.join()
            del statuses[username]
            report(headers,generatePublicKey(cherrypy.session['prikey']).encode(encoder=nacl.encoding.HexEncoder).decode('utf-8'),"offline")
            cherrypy.lib.sessions.expire()
        raise cherrypy.HTTPRedirect('/')


###
# Functions only after here
###

def make_headers(username,api_key):
    """Takes a username and an api_key and returns a header for authentication purposes
    
    Arguments:
        username {[string]} -- [The users username]
        api_key {[string]} -- [a current valid api key]
    
    Returns:
        [JSON] -- [the headers]
    """
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
    

def loadTime():
     """[This function will attempt to get the saved 
        time from the text file]
     """
     try:
         with open("time.txt",'r') as file:
             data= file.read()
         return data
     except:
         return ""

def saveTime():
     """[This function will save the last time a broadcast was recieved]
     """
     with open("time.txt",'w') as file:
         file.write(str(time.time()))
    
def remove_HTML_tags(message):
    """[Removes invalid HTML tags from a string]
    
    Arguments:
        message {[string]} -- [the input string]
    
    Returns:
        [string] -- [the cleaned string]
    """
    allowed_tags=['strong', 'em', 'ul', 'li', 'br','img','iframe']
    cleaned_message=""
    if message.find('<')==-1:
        return message
    while message.find('<')!=-1:
        cleaned_message+=message.split('<')[0]
        message=message[message.find('<')+1:]
        for i in allowed_tags:
            if message.split('>')[0].find(i)!=-1:
                cleaned_message+= "<"+message.split('>')[0]+">"
        message=message[message.find('>')+1:]
        
    return cleaned_message
    
def generatePrivateKey():
    """[To be used should there not be an existing private key.
        Takes no inputs but return a nacl.signing key]
    """
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
        status  {[string]}  --  [a string containing the users status, this is an optional argument and will default to online if not provided]
    """
    url = "http://cs302.kiwi.land/api/report"
    payload = {
        "connection_address": get_ip()+":10050",
        "connection_location": 1,
        "incoming_pubkey": pubkey_hex_str,
        "status":status
    }
    json=urlSend(url, headers, payload)
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
        address {[string]}  --  [the address of the recipient]
    
    Returns:
        [boolean] -- [true on sucess, false on failiure]
    """
    alt=False
    try:
        ping_check(headers,address)
    except:
        alt=True
    url = "http://"+address+"/api/rx_privatemessage"
    if not(target_user =='admin'):
        headers={
            'Content-Type': 'application/json; charset=utf-8',
        }
    now=str(time.time())
    publickey = target_pubkey.to_curve25519_public_key()
    sealed_box = nacl.public.SealedBox(publickey)
    encrypted = sealed_box.encrypt(bytes(message[1:],encoding='utf-8'), encoder=nacl.encoding.HexEncoder)
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
    array=list_address(headers)
    for i in array:
        try:
            ping_check(headers,i)
            address=i
            break
        except:
            continue
    url = "http://"+address+"/api/rx_privatemessage"
    try:
        if (urlSend(url,headers,payload))['response']=='ok':
            return True
        else:
            return False
    except KeyError:
        return False
  
def publicMessage(headers,message,prikey):
    """[Sends a public message to the login server]
    
    Arguments:
        headers {[JSON]}  --  [The authentication headers]
        message {[string]} -- [the message to be sent]
        prikey  {[SigningKey]}  --  [the current signing key in use]
    """
    address_list=list_address(headers)
    for i in address_list:
        url="http://"+i+"/api/rx_broadcast"
        try:
            ping_check(headers,i)
        except urllib.error.URLError:
            continue
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
                urlSend(url,blank_headers,payload)
            except:
                print()
        else:
            urlSend(url,headers,payload)

    
def getUsers(headers):   
    """[gets a list of users from the login server]
    
    Returns:
        [JSON] -- [a dict containing a single element 'users' which contains a list containing each users data in a dict]
    """
    url="http://cs302.kiwi.land/api/list_users" 
    payload=""
    data= urlSend(url,headers,payload)
    return data
    
def send_private_data(headers,username,unique,prikeys,pubkeys,b_username,words,b_signature,f_signature,f_username): 
    """Save the users private data
    
    Arguments:
        headers {[JSON]} -- [the authentication headers]
        username {[string]} -- [the current users username]
        unique {[string]} -- [the unique encryption password]
        prikeys {[list]} -- [the list of the users private keys]
        pubkeys {[list]} -- [the list of the users blocked public keys]
        b_username {[list]} -- [the list of the users blocked usernames]
        words {[list]} -- [the list of the users blocked words]
        b_signature {[list]} -- [the list of the users blocked signatures]
        f_signature {[list]} -- [the list of the users favourited signatures]
        f_username {[list]} -- [the list of the users favourited usernames]
    """
    now=str(time.time())
    pubkey_hex_str=generatePublicKey(prikeys[-1]).encode(encoder=nacl.encoding.HexEncoder).decode('utf-8')
    url="http://cs302.kiwi.land/api/add_privatedata" 
    record=getLoginserverRecord(headers,username,pubkey_hex_str)
    prikeys_str=prikeys
    for i in range(0,len(prikeys)):
        prikeys_str[i]=prikeys[i].encode(encoder=nacl.encoding.HexEncoder).decode('utf-8')
                                            
    pridata={   
        "prikeys": (prikeys_str),
        "blocked_pubkeys": pubkeys,
        "blocked_usernames": b_username,
        "blocked_words": words,
        "blocked_message_signatures": b_signature,
        "favourite_message_signatures": f_signature,
        "friends_usernames": f_username
    }
    pridata=(json.dumps(pridata).encode('utf-8'))
    
    key=nacl.pwhash.argon2i.kdf(32,unique.encode('utf-8'),(unique*16).encode('utf-8')[:16],opslimit=nacl.pwhash.argon2i.OPSLIMIT_SENSITIVE,memlimit=nacl.pwhash.argon2i.MEMLIMIT_SENSITIVE,encoder=nacl.encoding.RawEncoder)
    box = nacl.secret.SecretBox(key)
    
    nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)

    encrypted = (base64.b64encode(box.encrypt(pridata, nonce))).decode('utf-8')
    
    message_bytes = bytes(encrypted + record+now, encoding='utf-8')
    signing_key1=nacl.signing.SigningKey(bytes(prikeys[-1], encoding='utf-8'),encoder=nacl.encoding.HexEncoder)
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
    urlSend(url,headers,payload)

def recieve_private_data(headers,unique):
    """[This will retrieve the users saved private data]
    
    Arguments:
        headers {[JSON]} -- [the authentication headers]
        unique {[string]} -- [the unique encryption password]
    
    Returns:
        [dict] -- [a dictionary containing the private data]
    """
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
    """[List the available address's]
    
    Arguments:
        headers {[JSON]} -- [the authentication headers]
    
    Returns:
        [list] -- [a list of IP's]
    """
    users=getUsers(headers)['users']
    accepted_users=['ksae900','rgos933','gwon383','mpat750']
    output=[]
    for i in users:
        if i['username'] in accepted_users and i['connection_location']=="0":
            output.append(i['connection_address'])
    return output 

def check_pubkey(headers,pub_key):
    """[returns the loginserver_record for a given pubkey]
    
    Arguments:
        headers {[JSON]} -- [the authentication headers]
        pub_key {[String]} -- [the pubkey to verify]
    
    Returns:
        [dict] -- [the loginserver_record]
    """
    url="http://cs302.kiwi.land/api/check_pubkey?pubkey="+pub_key 
    payload={}
    return urlSend(url,headers,payload)

def check_messages(headers):
    """[Calls the checkmessages api on other clients]
    
    Arguments:
        headers {[JSON]} -- [the authentication headers]
    """
    address=list_address(headers)
    public=[]
    private=[]
    print(address)
    for i in address:
        if not (i == get_ip()+":10050"):
            url="http://"+i+"/api/checkmessages?since="+loadTime()
            payload={}
            try:
                JSON=urlSend(url,headers,payload)
                try:
                    for j in JSON['broadcasts']:
                        public.append(j)
                    for j in JSON['private_messages']:
                        private.append(j)
                    break
                except TypeError:
                    continue
            except:
                continue
    
    conn = sqlite3.connect("priv.db")
    cur = conn.cursor() 
    for i in private:
        cur.execute("""SELECT COUNT (id)  FROM privmessages;""")
        result=cur.fetchone()
                    
        cur.execute("INSERT INTO privmessages (id,message,recieved_at,sender)VALUES (?,?,?,?)",(str(int(result[0])+1), str(i),str(i["sender_created_at"]),i['loginserver_record'].split(',')[0],))
        conn.commit()
                    
    conn.close()
    conn = sqlite3.connect("my.db")
    c = conn.cursor() 
    
    for i in public:
                
        c.execute("""SELECT COUNT (id)  FROM pubmessages;""")
        result=c.fetchone()
                    
        c.execute("INSERT INTO pubmessages (id,message,recieved_at,sender)VALUES (?,?,?,?)",(str(int(result[0])+1), str(i),str(i["sender_created_at"]),i['loginserver_record'].split(',')[0],))
   
    conn.commit()
    conn.close()
    
    
def ping_check(headers,address):
    """[Performs a ping check on the address provided]
    
    Arguments:
        headers {[JSON]} -- [the authentication headers]
        address {[string]} -- [the ip address of the target]
    
    Returns:
        [JSON] -- [the response from the ping check]
    """
    url="http://"+address+"/api/ping_check"
    payload={  
            "my_time": str(time.time()),
            "connection_address": get_ip(),  
            "connection_location": 1}
    return urlSend(url,headers,payload)
    
def refresh_user():
    """[The target for the thread which keeps a user active]
    """
    global headers
    global pubkey_hex_str
    global e
    global statuses
    while not e.wait(timeout=180):
        print(statuses)
        for i in statuses.keys():
            make_headers(i,statuses[i][0])
            report(headers,pubkey_hex_str,statuses[i][1])
    
def worker():
    """[The thread constructor function]
    
    Returns:
        [Thread] -- [the thread]
    """
    global e
    e.clear()
    t=threading.Thread(target=refresh_user)
    t.daemon=True
    t.start()
    return t
    
def get_ip():
    """[gets the machine ip]
    
    Returns:
        [string] -- [the machines ip]
    """
    #ip address extraction
    ip_command =check_output(["hostname","-I"])
    ip_string = ip_command.decode('utf-8')
    ip_add = ip_string[:len(ip_string)-2]
    if not(ip_add.find(' ')==-1):
        ip_add=ip_add.split(' ')[0]
    return ip_add
    
def get_apikey(username,password):
    """[Gets the API key for a user given appropriate authentication]
    
    Arguments:
        username {[string]} -- [the users username]
        password {[string]} -- [the users password]
    
    Returns:
        [string] -- [the API key for the session]
    """
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
    """[Authorise the user with the login server]
    
    Arguments:
        username {[string]} -- [the users username]
        password {[string]} -- [the asscociated password]
        header {[JSON]} -- [the authentication header]
        unique {[string]} -- [the unique encryption password]
        prikey {[SigningKey]} -- [the users private key]
    
    Returns:
        [int] -- [the code corresponding to the result, 0=OK,1=Bad login,2=no connection]
    """
    global headers
    global pubkey_hex_str
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
        check_messages(headers)
        if report(headers,pubkey_hex_str)['response'] == 'error':
            return 1
        return 0
    except urllib.error.HTTPError as error:
        print(error.read())
        return 1
    except urllib.error.URLError as error:
        return 2