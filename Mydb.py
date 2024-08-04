import mysql.connector

dataBase = mysql.connector.connect(
	host = 'GuruTechDev.mysql.pythonanywhere-services.com',
	user = 'GuruTechDev',
	passwd = 'data@1234'

	)

# prepare a cursor object
cursorObject = dataBase.cursor()

# Create a database
cursorObject.execute("CREATE DATABASE gurutech$default")

print("All Done!")
