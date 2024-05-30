from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi
from urllib.parse import quote_plus
import config

mongoUser = config.username
mongoPass = config.password

encoded_username = quote_plus(mongoUser)
encoded_password = quote_plus(mongoPass)

uri = f"mongodb+srv://{encoded_username}:{encoded_password}@cluster0.q5bthyd.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"

# Create a new client and connect to the server
client = MongoClient(uri, server_api=ServerApi('1'))

# Pinging to check a successful connection
try:
    client.admin.command('ping')
    print("Pinged your deployment. You successfully connected to MongoDB!")
except Exception as e:
    print(e)
