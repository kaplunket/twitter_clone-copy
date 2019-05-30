import sqlite3
conn = sqlite3.connect("my.db")
#get the cursor (this is what we use to interact)
c = conn.cursor() 
#create table
#c.execute("""CREATE TABLE users

#            (id INTEGER PRIMARY KEY NOT NULL, username TEXT
#             UNIQUE, password TEXT, age INTEGER)""")
#conn.commit()
c.execute("INSERT INTO users (id,username,password,age)VALUES (1,'admin','test',20)")
#conn.commit()
cur = conn.cursor()
cur.execute("SELECT * FROM users")
 
rows = cur.fetchall()

for row in rows:
    print(row)
    
conn.close()