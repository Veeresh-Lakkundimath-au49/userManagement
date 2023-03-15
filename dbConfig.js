const { MongoClient } = require('mongodb')

const dbName = 'userManagement'
let url="mongodb+srv://VeereshCluster:1234@veereshcluster.dpxprjq.mongodb.net/test"

async function initDB() {
  const client = new MongoClient(url)

  // 1) Connect
  // 2) Db Name
  // 3) Collection Name
  try {
    await client.connect()
    const db = client.db(dbName)
    const collection = db.collection('userData')
    console.log("Successfully Connected to DB")

    return collection
  } catch (err) {
    console.log("Error Connection to DB")
  }

}

module.exports = {
  initDB
}