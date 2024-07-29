from pymongo import MongoClient

ALGORITHM = "HS256"

def get_database_connection(db_url):
    client = MongoClient(db_url, tls=True)
    db = client["umax"]
    foto_collection = db["foto"]
    timezone_collection = db["timezone"] 
    currency_collection = db["currency"] 
    culture_collection = db["culture"]
    campaigns_collection = db["campaigns"]
    accounts_collection = db["accounts"]
    clients_collection = db["clients"] 
    user_collection = db["user"] 
    dashboard_collection = db["dashboard"] 
    history_collection = db["history"] 
    metrics_collection = db["metrics"]  
    profil_collection = db["profil"] 
    settings_collection = db["settings"] 
    tenant_collection = db["tenant"]
    return client, db, foto_collection, timezone_collection, currency_collection, culture_collection, campaigns_collection, accounts_collection, clients_collection, user_collection, dashboard_collection, history_collection, metrics_collection, profil_collection, settings_collection, tenant_collection

SECRET_KEY = "thisisverysecretsuperadminpassword"
ALGORITHM = "HS256"