from flask import *
import sqlite3, hashlib, os
from werkzeug.utils import secure_filename
import socket
import sys
import smtplib
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA512, SHA384, SHA256, SHA, MD5
from Crypto import Random
from base64 import b64encode, b64decode

app = Flask(__name__)
app.secret_key = 'random string'
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = set(['jpeg', 'jpg', 'png', 'gif'])
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
hash = "SHA-256"

def newkeys(keysize):
    random_generator = Random.new().read
    key = RSA.generate(keysize, random_generator)
    private, public = key, key.publickey()
    return public, private

def importKey(externKey):
    return RSA.importKey(externKey)

def getpublickey(priv_key):
    return priv_key.publickey()
def encrypt(message, pub_key):
    #RSA encryption protocol according to PKCS#1 OAEP
    cipher = PKCS1_OAEP.new(pub_key)
    return cipher.encrypt(message)

def decrypt(ciphertext, priv_key):
    #RSA encryption protocol according to PKCS#1 OAEP
    cipher = PKCS1_OAEP.new(priv_key)
    return cipher.decrypt(ciphertext)

def sign(message, priv_key, hashAlg="SHA-256"):
    global hash
    hash = hashAlg
    signer = PKCS1_v1_5.new(priv_key)
    if (hash == "SHA-512"):
        digest = SHA512.new()
    elif (hash == "SHA-384"):
        digest = SHA384.new()
    elif (hash == "SHA-256"):
        digest = SHA256.new()
    elif (hash == "SHA-1"):
        digest = SHA.new()
    else:
        digest = MD5.new()
    digest.update(message)
    return signer.sign(digest)

def verify2(message, signature, pub_key):
    signer = PKCS1_v1_5.new(pub_key)
	
    if (hash == "SHA-512"):
        digest = SHA512.new()
    elif (hash == "SHA-384"):
        digest = SHA384.new()
    elif (hash == "SHA-256"):
        digest = SHA256.new()
    elif (hash == "SHA-1"):
        digest = SHA.new()
    else:
        digest = MD5.new()
    digest.update(message)
    return signer.verify(digest, signature)

def getLoginDetails():
    with sqlite3.connect('database.cmpe_web') as conn:
        cur = conn.cursor()
        if 'email' not in session:
            loggedIn = False
            firstName = ''
            noOfItems = 0
  
        else:
            loggedIn = True
            cur.execute("SELECT userId, firstName FROM users WHERE email = '" + session['email'] + "'")
            userId, firstName = cur.fetchone()
            cur.execute("SELECT count(productId) FROM cart WHERE userId = " + str(userId))
            noOfItems = cur.fetchone()[0]
    conn.close()
    return (loggedIn, firstName, noOfItems)

@app.route("/loginForm")
def loginForm():
    if 'email' in session:
        return redirect(url_for('root'))
    else:
        return render_template('login.html', error='')

@app.route("/login", methods = ['POST', 'GET'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        if (is_valid(email, password)):
            session['email'] = email
            return redirect(url_for('root'))
        else:
            error = 'Invalid UserId / Password'
            return render_template('login.html', error=error)

@app.route("/logout")
def logout():
    session.pop('email', None)
    return redirect(url_for('root'))

def is_valid(email, password):
    con = sqlite3.connect('database.cmpe_web')
    cur = con.cursor()
    cur.execute('SELECT email, password FROM users')
    data = cur.fetchall()
    for row in data:
        if row[0] == email and row[1] == hashlib.md5(password.encode()).hexdigest():
            return True
    return False

@app.route("/register", methods = ['GET', 'POST'])
def register():
    if request.method == 'POST':
        #Parse form data    
        password = request.form['password']
        email = request.form['email']
        firstName = request.form['firstName']
        lastName = request.form['lastName']
        address1 = request.form['address1']
        address2 = request.form['address2']
        zipcode = request.form['zipcode']
        city = request.form['city']
        state = request.form['state']
        country = request.form['country']
        phone = request.form['phone']

        with sqlite3.connect('database.cmpe_web') as con:
            try:
                cur = con.cursor()
                cur.execute('INSERT INTO users (password, email, firstName, lastName, address1, address2, zipcode, city, state, country, phone) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)', (hashlib.md5(password.encode()).hexdigest(), email, firstName, lastName, address1, address2, zipcode, city, state, country, phone))
                con.commit()
                msg = "Registered Successfully"
            except:
                con.rollback()
                msg = "Error occured"
        con.close()
        return render_template("login.html", error=msg)

@app.route("/registerationForm")
def registrationForm():
    return render_template("register.html")

@app.route("/")
def root():
    loggedIn = False
    noOfItems = 0
    if 'email' not in session:
        loggedIn = False
        noOfItems = 0
        firstName = ''
    else:
        loggedIn, firstName, noOfItems = getLoginDetails()
    with sqlite3.connect('database.cmpe_web') as conn:
        cur = conn.cursor()
        cur.execute('SELECT productId, name, price, description, image, stock FROM products')
        itemData = cur.fetchall()
    itemData = parse(itemData)  
    return render_template('home.html', itemData=itemData, loggedIn=loggedIn, firstName=firstName, noOfItems=noOfItems)

@app.route("/add")
def admin():
    return render_template('add.html')

@app.route("/addItem", methods=["GET", "POST"])
def addItem():
    if request.method == "POST":
        name = request.form['name']
        price = float(request.form['price'])
        description = request.form['description']
        stock = int(request.form['stock'])

        #Uploading image procedure
        image = request.files['image']
        if image and allowed_file(image.filename):
            filename = secure_filename(image.filename)
            image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        imagename = filename
        with sqlite3.connect('database.cmpe_web') as conn:
            try:
                cur = conn.cursor()
                cur.execute('''INSERT INTO products (name, price, description, image, stock) VALUES (?, ?, ?, ?, ?)''', (name, price, description, imagename, stock))
                conn.commit()
                msg="Added successfully"
            except:
                msg="Error occured"
                conn.rollback()
        conn.close()
        return render_template('add.html', msg=msg)

@app.route("/remove")
def remove():
    with sqlite3.connect('database.cmpe_web') as conn:
        cur = conn.cursor()
        cur.execute('SELECT productId, name, price, description, image, stock FROM products')
        data = cur.fetchall()
    conn.close()
    return render_template('remove.html', data=data)

@app.route("/removeItem")
def removeItem():
    productId = request.args.get('productId')
    with sqlite3.connect('database.cmpe_web') as conn:
        try:
            cur = conn.cursor()
            cur.execute('DELETE FROM products WHERE productID = ' + productId)
            conn.commit()
            msg = "Deleted successsfully"
            cur.execute('SELECT productId, name, price, description, image, stock FROM products')
            data = cur.fetchall()
        except:
            conn.rollback()
            msg = "Error occured"
    conn.close()
    return render_template('remove.html', data=data)

@app.route("/account/orders")
def orderupdate():
    if 'email' not in session:
        return redirect(url_for('root'))
    loggedIn, firstName, noOfItems = getLoginDetails()
    with sqlite3.connect('database.cmpe_web') as conn:
            cur = conn.cursor()
            cur.execute("SELECT userId FROM users WHERE email = '" + session['email'] + "'")
            userId = cur.fetchone()[0]
            cur.execute("SELECT orderid FROM  orders WHERE userId = " + str(userId) + " order by timestamp desc limit 1")
            orderid=cur.fetchone()[0]
            cur.execute("SELECT flag FROM  orders WHERE orderid="+str(orderid))
            flag=cur.fetchone()[0]
            if(flag=='True'):
                flag='Approved'
            else:
                flag='Awaiting approval'
    conn.close()
    return render_template("orderstatus.html", loggedIn=loggedIn, firstName=firstName, noOfItems=noOfItems, userId=userId,flag=flag,orderid=orderid)

@app.route("/account/profile")
def profileHome():
    if 'email' not in session:
        return redirect(url_for('root'))
    loggedIn, firstName, noOfItems = getLoginDetails()
    with sqlite3.connect('database.cmpe_web') as conn:
        cur = conn.cursor()
        cur.execute("SELECT userId, email, firstName, lastName, address1, address2, zipcode, city, state, country, phone FROM users WHERE email = '" + session['email'] + "'")
        profileData = cur.fetchone()
    conn.close()
    return render_template("profileHome.html", profileData=profileData, loggedIn=loggedIn, firstName=firstName, noOfItems=noOfItems)

@app.route("/account/profile/changePassword", methods=["GET", "POST"])
def changePassword():
    if 'email' not in session:
        return redirect(url_for('loginForm'))
    if request.method == "POST":
        oldPassword = request.form['oldpassword']
        oldPassword = hashlib.md5(oldPassword.encode()).hexdigest()
        newPassword = request.form['newpassword']
        newPassword = hashlib.md5(newPassword.encode()).hexdigest()
        with sqlite3.connect('database.cmpe_web') as conn:
            cur = conn.cursor()
            cur.execute("SELECT userId, password FROM users WHERE email = '" + session['email'] + "'")
            userId, password = cur.fetchone()
            if (password == oldPassword):
                try:
                    cur.execute("UPDATE users SET password = ? WHERE userId = ?", (newPassword, userId))
                    conn.commit()
                    msg="Changed successfully"
                except:
                    conn.rollback()
                    msg = "Failed"
                return render_template("changePassword.html", msg=msg)
            else:
                msg = "Wrong password"
        conn.close()
        return render_template("changePassword.html", msg=msg)
    else:
        return render_template("changePassword.html")

@app.route("/updateProfile", methods=["GET", "POST"])
def updateProfile():
    if request.method == 'POST':
        email = request.form['email']
        firstName = request.form['firstName']
        lastName = request.form['lastName']
        address1 = request.form['address1']
        address2 = request.form['address2']
        zipcode = request.form['zipcode']
        city = request.form['city']
        state = request.form['state']
        country = request.form['country']
        phone = request.form['phone']
        with sqlite3.connect('database.cmpe_web') as con:
                try:
                    cur = con.cursor()
                    cur.execute('UPDATE users SET firstName = ?, lastName = ?, address1 = ?, address2 = ?, zipcode = ?, city = ?, state = ?, country = ?, phone = ? WHERE email = ?', (firstName, lastName, address1, address2, zipcode, city, state, country, phone, email))
                    con.commit()
                    msg = "Saved Successfully"
                except:
                    con.rollback()
                    msg = "Error occured"
        con.close()
        return redirect(url_for('editProfile'))

@app.route("/productDescription")
def productDescription():
    loggedIn, firstName, noOfItems = getLoginDetails()
    productId = request.args.get('productId')
    with sqlite3.connect('database.cmpe_web') as conn:
        cur = conn.cursor()
        cur.execute('SELECT productId, name, price, description, image, stock FROM products WHERE productId = ' + productId)
        productData = cur.fetchone()
    conn.close()
    return render_template("productDescription.html", data=productData, loggedIn = loggedIn, firstName = firstName, noOfItems = noOfItems)

@app.route("/addToCart")
def addToCart():
    if 'email' not in session:
        return redirect(url_for('loginForm'))
    else:
        productId = int(request.args.get('productId'))
        with sqlite3.connect('database.cmpe_web') as conn:
            cur = conn.cursor()
            cur.execute("SELECT userId FROM users WHERE email = '" + session['email'] + "'")
            userId = cur.fetchone()[0]
            try:
                cur.execute("INSERT INTO cart (userId, productId) VALUES (?, ?)", (userId, productId))
                conn.commit()
                msg = "Added successfully"
            except:
                conn.rollback()
                msg = "Error occured"
        conn.close()
        return redirect(url_for('root'))

@app.route("/cart")
def cart():
    if 'email' not in session:
        return redirect(url_for('loginForm'))
    loggedIn, firstName, noOfItems = getLoginDetails()
    email = session['email']
    with sqlite3.connect('database.cmpe_web') as conn:
        cur = conn.cursor()
        cur.execute("SELECT userId FROM users WHERE email = '" + email + "'")
        userId = cur.fetchone()[0]
        cur.execute("SELECT products.productId, products.name, products.price, products.image FROM products, cart WHERE products.productId = cart.productId AND cart.userId = " + str(userId))
        products = cur.fetchall()
    totalPrice = 0
    for row in products:
        totalPrice += row[2]
    return render_template("cart.html", products = products, totalPrice=totalPrice, loggedIn=loggedIn, firstName=firstName, noOfItems=noOfItems)

@app.route("/removeFromCart")
def removeFromCart():
    if 'email' not in session:
        return redirect(url_for('loginForm'))
    email = session['email']
    productId = int(request.args.get('productId'))
    with sqlite3.connect('database.cmpe_web') as conn:
        cur = conn.cursor()
        cur.execute("SELECT userId FROM users WHERE email = '" + email + "'")
        userId = cur.fetchone()[0]
        try:
            cur.execute("DELETE FROM cart WHERE userId = " + str(userId) + " AND productId = " + str(productId))
            conn.commit()
            msg = "removed successfully"
        except:
            conn.rollback()
            msg = "error occured"
    conn.close()
    return redirect(url_for('cart'))

@app.route("/checkout", methods = ['POST', 'GET'])
def checkout():
    if 'email' not in session:
        return redirect(url_for('loginForm'))
    loggedIn, firstName, noOfItems = getLoginDetails()
    msg = ''
    if request.method == 'POST':
        card = request.form['card']
        email = session['email']
        with sqlite3.connect('database.cmpe_web') as conn:
            try:
                cur = conn.cursor()
                cur.execute("SELECT userId FROM users WHERE email = '" + email + "'")
                userId = cur.fetchone()[0]
                cur.execute("SELECT productId FROM  cart WHERE userId = " + str(userId))
                productId = cur.fetchone()[0]
                flag='false'
             
                cur.execute("INSERT INTO orders (userId, productId,flag) VALUES (?, ?,?)", (userId, productId,flag))
                conn.commit()

                #sending email for approval
                cur.execute("SELECT orderid, timestamp FROM  orders WHERE userId = " + str(userId) + " order by timestamp desc limit 1" )
                orderData = cur.fetchone()
                orderid = orderData[0]
                timestamp = orderData[1]
                message = str(userId)+str(orderid)+str(timestamp)
                message = message.encode()
                privateuser='-----BEGIN RSA PRIVATE KEY-----\nMIICWwIBAAKBgQC6OHWNGCAizb/DGi3JDbD54go0HaWTnyaR5Le7k2EE4Gqm3oCX\nH9fD0WQoOoXvGEeki0FbKkqAcPjZ0kFxY3xtPWiofhokwismJG3ZO1NHAGVtetM1\nVRQ+usRmuVtQZi91KBAL7buf50oJl8gQDtRtDT6WVH1Lk0AaP0bFEEsxVQIDAQAB\nAoGAEqGleTlptbG6Nu3+mLgK9eVcufwhXdS1ijFFBLppIZDGeu2WFgi0kL35dGDu\nl45pVJguMM3ZaGJlM33q2Epo32UXW9arvhPY+m/6BzOWH4iW4OAqlHvjTx+abajZ\nuHHGR/6g/Z/LWNiSTGFWYPg1apwQpAlw3AULGZjRCeqyUt0CQQDA2THKcBCZv3uu\ntlbhCz1QvoEHenB6AIpKyfFLlrZGjAUcBIJExoyHC8e/K7Lk1gYaiRun8f2JqCFs\nlHyg2ghHAkEA9zOjmWfBe4AS5kvm3Ml1TDwCAAmG4KEJjY0DViHwxy3t9jiVJZTP\nwgnTSu+XCm672J5wtwzyNsLGvC7qjI7jgwJAZf+6pQ7myNsNaNgKVZcjRByulCz/\nZpf4jRwIYumA2Qlf/nSoDgZR92+Uo5lSUlSc/9X66bZFWlSx8QMMc+s+KwJATpp9\n796dGE8eM1p5O0VX5fjCzg45dB3gssDfCblbHYqOOxe83SlXcqS7Kf3LMkcJthST\nVLFqJ12B4f6tGCqrTwJAThXpA3lP5tt7T20wMEJpwUstDkH0oQvH6LdsjENGs1Tn\nAjjyjJr1072nIAf6sQNmvuNr8hqodwtM84drGTj2iQ==\n-----END RSA PRIVATE KEY-----'
                privateU = importKey(privateuser)
                signature = b64encode(sign(message, privateU, "SHA-256"))
                subject = "Order ID " +str(orderid)+" waiting for your approval"
                body = str(signature)
                recipients = 'supervisorDepartment209@gmail.com' 
                gmail_user = 'purchaseDepartment209@gmail.com'
                gmail_pwd = 'Sjsucmpe209'
                smtpserver = smtplib.SMTP("smtp.gmail.com",587)
                smtpserver.ehlo()
                smtpserver.starttls()
                smtpserver.ehlo()
                smtpserver.login(gmail_user, gmail_pwd)
                header = 'To:' + recipients + '\n' + 'From: ' + gmail_user + '\n' + 'Subject:' + subject + ' \n'
                msg = header + '\n' + body + '\n\n'
                smtpserver.sendmail(gmail_user, recipients.split(', '), msg)
                smtpserver.close()
                msg="Order sent for approval"
            except:
                conn.rollback()
                msg="Error occured"
        conn.close()
    return render_template("checkout.html",loggedIn=loggedIn, firstName=firstName, noOfItems=noOfItems,msg=msg)
    
def allowed_file(filename):
    return '.' in filename and \
            filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS

def parse(data):
    ans = []
    i = 0
    while i < len(data):
        curr = []
        for j in range(7):
            if i >= len(data):
                break
            curr.append(data[i])
            i += 1
        ans.append(curr)
    return ans

if __name__ == '__main__':
    app.run(debug=True)
