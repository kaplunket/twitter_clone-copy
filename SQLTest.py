import sqlite3
conn = sqlite3.connect("my.db")
#get the cursor (this is what we use to interact)
c = conn.cursor() 
#create table
#c.execute("""CREATE TABLE users

#            (id INTEGER PRIMARY KEY NOT NULL, username TEXT
#             UNIQUE, password TEXT, age INTEGER)""")
#conn.commit()

#TODO password should not be stored and keys should be stored instead, keys should be encrypted or something via password
#safer that way and password should be verified by login server before attempt decryption
#STuff to be stored:
#username,private key, public key, last login time, or maybe stored in the login server?, or maybe do a double comparison
# we may not need to store anything?
#private messages recieved should be stored encrypted, but all other stuff could be verified against the server
#Hmmmm
c.execute("INSERT INTO users (id,username,password,age)VALUES (4,'python','test',20)")
#conn.commit()
cur = conn.cursor()
cur.execute("SELECT * FROM users")
 
rows = cur.fetchall()
for row in rows:
    print(row)
    
conn.close()