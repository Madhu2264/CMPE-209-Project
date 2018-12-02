import sqlite3

#Open database
conn = sqlite3.connect('database.cmpe_web')


#Create table
conn.execute('''CREATE TABLE users 
		(userId INTEGER PRIMARY KEY,
		password TEXT,
		email TEXT,
		firstName TEXT,
		lastName TEXT,
		address1 TEXT,
		address2 TEXT,
		zipcode TEXT,
		city TEXT,
		state TEXT,
		country TEXT, 
		phone TEXT
		)''')

conn.execute('''CREATE TABLE products
		(productId INTEGER PRIMARY KEY,
		name TEXT,
		price REAL,
		description TEXT,
		image TEXT,
		stock INTEGER
		)''')

conn.execute('''CREATE TABLE cart
		(userId INTEGER,
		productId INTEGER,
		FOREIGN KEY(userId) REFERENCES users(userId),
		FOREIGN KEY(productId) REFERENCES products(productId)
		)''')

conn.execute('''CREATE TABLE orders
		(orderId INTEGER PRIMARY KEY,
		userId INTEGER,
		productId INTEGER,
		flag TEXT,
		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY(userId) REFERENCES users(userId),
		FOREIGN KEY(productId) REFERENCES products(productId)
		)''')

conn.close()

