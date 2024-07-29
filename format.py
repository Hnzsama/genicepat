import pymongo
import json

# Membaca data dari file JSON
with open('timezones.json') as file:
    data = json.load(file)

# Menghubungkan ke database MongoDB
client = pymongo.MongoClient('mongodb://localhost:27017/')
database = client['umax']
collection = database['currencysymbol']

# Memasukkan setiap zona waktu sebagai dokumen terpisah ke dalam koleksi MongoDB
for document in data:
    # Mengambil nilai "cultureInfoCode" dan melakukan transformasi dengan mengganti tanda strip menjadi underscore
    culture_info_code = document.get('cultureInfoCode', '').replace('-', '_')
    country = document.get('country', '')

    # Menyiapkan dokumen untuk dimasukkan ke dalam koleksi MongoDB
    document_to_insert = {
        'cultureInfoCode': culture_info_code,
        'country': country
    }

    # Memasukkan dokumen ke dalam koleksi MongoDB
    collection.insert_one(document_to_insert)

# Menampilkan pesan berhasil
print("Data berhasil dimasukkan ke koleksi 'culture' di database 'umax'.")