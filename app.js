const express=require('express')
const app=express();
//app.listen(8000)

let jwt = require('jsonwebtoken')
// var CryptoJS = require("crypto-js");
let cookieParser = require('cookie-parser')
app.use(cookieParser())

app.use(express.json()) 
let {signup,login,logout,user,resetPass,editUser}=require("./controllers/controllers")

app.get('/',(req,res)=>{
    res.send("Server started successfully at port 8000")
    console.log("Server started successfully!")
})

app.post("/login",login)

app.post('/signup',signup)

app.get('/logout',logout)

app.post('/resetPass',resetPass)

app.get('/user',user)

app.post('/editUser',editUser)

const PORT = 8000
app.listen(PORT,()=>{
    console.log('server is runing');
    
}) 




















// // 

// var CryptoJS = require("crypto-js");

// // Encrypt
// var ciphertext = CryptoJS.AES.encrypt('Veeresh FSD', 'secret key 123').toString();

// // Decrypt
// var bytes  = CryptoJS.AES.decrypt(ciphertext, 'secret key 123');
// var originalText = bytes.toString(CryptoJS.enc.Utf8);

// console.log(originalText); // 'my message'























// const crypto = require('crypto');

// // Define the plaintext and secret key
// const plaintext = 'This is a secret message';
// const secretKey = 'my secret key';

// // Create a cipher object using the secret key and set the mode to ECB
// const cipher = crypto.createCipheriv('aes-256-ecb', secretKey, '');

// // Encrypt the plaintext and get the output as a Buffer
// let encrypted = cipher.update(plaintext, 'utf8', 'hex');
// encrypted += cipher.final('hex');

// console.log('Encrypted message:', encrypted);




// // Create a decipher object using the secret key and set the mode to ECB
// const decipher = crypto.createDecipheriv('aes-256-ecb', secretKey, '');

// // Decrypt the message and get the output as a UTF-8 string
// let decrypted = decipher.update(encrypted, 'hex', 'utf8');
// decrypted += decipher.final('utf8');

// console.log('Decrypted message:', decrypted);

// if(encrypted==decrypted){
//     console.log("true");
// }
























// var CryptoJS = require("crypto-js");

// var data = [{id: 1}, {id: 2}]

// // Encrypt
// var ciphertext = CryptoJS.AES.encrypt(JSON.stringify(data), 'secret key 123').toString();

// // Decrypt
// var bytes  = CryptoJS.AES.decrypt(ciphertext, 'secret key 123');
// var decryptedData = JSON.parse(bytes.toString(CryptoJS.enc.Utf8));

// console.log(decryptedData); // [{id: 1}, {id: 2}]

























// const CryptoJS = require('node-cryptojs-aes').CryptoJS;

// function aes256ecb(input, key, encrypt) {
//   const mode = encrypt ? CryptoJS.mode.ECB : undefined;
//   const options = { mode };
//   const encrypted = CryptoJS.AES.encrypt(input, key, options);
//   const decrypted = CryptoJS.AES.decrypt(encrypted, key, options);
//   return encrypt ? encrypted.toString() : decrypted.toString(CryptoJS.enc.Utf8);
// }

// const plaintext = 'This is a secret message';
// const secretKey = 'my secret key';

// const encrypted = aes256ecb(plaintext, secretKey, true);
// console.log('Encrypted message:', encrypted);



// const decrypted = aes256ecb(encrypted, secretKey, false);
// console.log('Decrypted message:', decrypted);
















// const crypto = require('crypto');

// function encrypt(plaintext, key) {
//   const iv = Buffer.alloc(16, 0); // use a fixed IV
//   const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
//   const encrypted = cipher.update(plaintext, 'utf8', 'hex') + cipher.final('hex');
//   const tag = cipher.getAuthTag().toString('hex');
//   return encrypted + ':' + tag;
// }

// function decrypt(ciphertext, key) {
//   const [encrypted, tag] = ciphertext.split(':');
//   const iv = Buffer.alloc(16, 0); // use a fixed IV
//   const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
//   decipher.setAuthTag(Buffer.from(tag, 'hex'));
//   const decrypted = decipher.update(encrypted, 'hex', 'utf8') + decipher.final('utf8');
//   return decrypted;
// }

// const plaintext = 'hello world';
// const key = 'mysecretkey';

// const encrypted = encrypt(plaintext, key);
// console.log(encrypted); // outputs something like '7f63c11a616a270c686b0e27:17a0f43b38d87dbfc6172d0e0d548c28'

// const decrypted = decrypt(encrypted, key);
// console.log(decrypted); // outputs 'hello world'




// const Cryptr = require('cryptr');

// // create a new instance of Cryptr with a secret key
// const cryptr = new Cryptr('mySecretKey');

// // encrypt a string
// const encryptedString = cryptr.encrypt('myPassword');
// const encryptedString_1 = cryptr.encrypt('myPassword');

// if(encryptedString==encryptedString_1){

//     console.log("True");
// }
// else{
//     console.log("false");
// }

// // decrypt the encrypted string
// const decryptedString = cryptr.decrypt(encryptedString);

// console.log('Encrypted string:', encryptedString);
// console.log('Encrypted string:', encryptedString_1);
// console.log('Decrypted string:', decryptedString);




















// const Cryptr = require('cryptr');

// const secretKey = 'mySecretKey';
// const fixedSalt = 'myFixedSalt'; // set a fixed salt
// const fixedIV = 'myFixedIV123456';

// // create a new instance of Cryptr with a fixed salt
// //const cryptr = new Cryptr(secretKey, { salt: fixedSalt });
// const cryptr = new Cryptr(secretKey, { salt: fixedSalt, iv: fixedIV });

// // encrypt a string
// const encryptedString = cryptr.encrypt('myPassword');
// const AencryptedString = cryptr.encrypt('myPassword');


// console.log('Encrypted string1:', encryptedString); 
// console.log('Encrypted string2:', AencryptedString);
// // should be the same every time












// const Cryptr = require('cryptr');

// const secretKey = 'mySecretKey';
// const fixedSalt = 'myFixedSalt';
// const fixedIV = Buffer.from('myFixedIV1234567890');

// const cryptr = new Cryptr(secretKey, {
//   salt: fixedSalt,
//   algorithm: 'aes-256-cbc',
//   iv: fixedIV,
// });

// const encryptedString1 = cryptr.encrypt('myPassword');
// const encryptedString2 = cryptr.encrypt('myPassword');

// console.log('Encrypted string 1:', encryptedString1);
// console.log('Encrypted string 2:', encryptedString2);















// //FINAL BCRYPT HASHING EQUAL

// const bcrypt = require('bcrypt');

// // This is the old hashed password that was stored in the database
// const oldHashedPassword = '$2b$10$6UJPA6UZBC6UZBC6UJPA6UZBC6UZBC6UJPA6UZBC6UZBC6UJPA6U';

// // This is the new password that needs to be checked
// const newPassword = 'myNewPassword';

// // This is the salt that was used to hash the old password
//  const salt = '$2b$10$6UJPA6UZBC6UZBC6UJPA6U';


// // Hash the new password using the same salt
// const newHashedPassword = bcrypt.hashSync(newPassword, salt);
// const AnewHashedPassword = bcrypt.hashSync(newPassword, salt);

// // Compare the two hashed passwords
// if (newHashedPassword === AnewHashedPassword) {
//   console.log('Password matches');
// } else {
//   console.log('Password does not match');
// }

