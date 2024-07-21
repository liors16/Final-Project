from pymongo.mongo_client import MongoClient
from urllib.parse import quote_plus
import config

mongoUser = config.username
mongoPass = config.password

encoded_username = quote_plus(mongoUser)
encoded_password = quote_plus(mongoPass)

uri = f"mongodb+srv://{encoded_username}:{encoded_password}@cluster0.trnnkjn.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"
cluster = MongoClient(uri)
db = cluster[config.db_name]
collection = db[config.collection_name]

check1 = {"_id": 2, "name": "TEST1"}
check2 = {"_id": 3, "name": "TEST2"}

collection.insert_many([check1, check2])



# I want to create new function that will check if there is attached file in the message.
# If there is, so check if it contain links inside, if there is so extract them.
# If there is no links, so send the file to virustotal to check if it's malicious