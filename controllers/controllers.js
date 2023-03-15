let {initDB}=require('../dbConfig')
let jwt = require('jsonwebtoken')
var CryptoJS = require("crypto-js");
const bcrypt = require('bcrypt')
const salt = '$2b$10$6UJPA6UZBC6UZBC6UJPA6U';

let userCollection;
async function userColl(){
    userCollection=await initDB()
}

userColl()

let signup=async (req,res)=>{
    let {email,phNum,fName,password}=req.body;
    console.log(email,phNum,fName,password);

    

    const hashedPassword = await bcrypt.hash(password, salt)

    console.log("hashedPassword",hashedPassword);

  //  var data = [{email: email,phNum:phNum,fName:fName}]


    // Encrypt
    var encEmail = CryptoJS.AES.encrypt(email, 'secret key 123').toString();
    var encPhNum = CryptoJS.AES.encrypt(phNum, 'secret key 123').toString();
    var encFName = CryptoJS.AES.encrypt(fName, 'secret key 123').toString();

    try {
        
        let newUser = await userCollection.insertOne({ 'name': encFName, 'email': encEmail, 'password': hashedPassword,'number':encPhNum})
        res.send("SignUp successful!!")
    } catch (error) {
        
        console.log("Error in SignUp",error)
        res.send("Error in SignUp")
    }

}

let login=async (req,res)=>{
    let{email,password}=req.body;
    
    console.log("line 44",email,password);
    let passAsCondition = await bcrypt.hash(password, salt)

    let credentials=await userCollection.findOne({'password':passAsCondition})



    
    if(!credentials){
        res.send("Invalid Credentials!")
    }
    else{

        //     Decrypt
        var bytes  = CryptoJS.AES.decrypt(credentials.email, 'secret key 123');
        var decryptedData = bytes.toString(CryptoJS.enc.Utf8);

        if(decryptedData===email){

            let userPayload = { email:decryptedData, password:credentials.password };
            console.log("userPayload,line 60",userPayload);
            // console.log(userPayload);
            let token = jwt.sign(userPayload,'jwtKey', { expiresIn: '1d' })
            // console.log(token);
            res.cookie('jwt', token)
            res.send("login successfull!")


        }
        else{
            res.send("Invalid credentials")
        }

       
    }

    
}

let logout = (req, res) => {
    res.cookie('jwt', '')
    res.send("Log out successfull!")
    
    console.log('logout');
}

let user=async(req,res)=>{

    let token = req.cookies.jwt
        if(token){
        let userdata = jwt.verify(token,'jwtKey')
        let { email, password } = userdata;
        console.log(email,password);

        var bytes  = CryptoJS.AES.decrypt(userdata.email, 'secret key 123');
        var decryptedEmail = JSON.parse(bytes.toString(CryptoJS.enc.Utf8));

        

        try {
            
            let asCondition=CryptoJS.AES.encrypt(decryptedEmail, 'secret key 123').toString();
            let userInfo=await userCollection.find({"email":asCondition})
            if(!userInfo){
                res.send("Email Id invalid, Please signup and then try to login")
            }
            else{


                // Decrypt

                let bytes;
                  bytes  = CryptoJS.AES.decrypt(userInfo.name, 'secret key 123');
                 var decryptedName = JSON.parse(bytes.toString(CryptoJS.enc.Utf8));

                  bytes  = CryptoJS.AES.decrypt(userInfo.number, 'secret key 123');
                 var decryptedNumber = JSON.parse(bytes.toString(CryptoJS.enc.Utf8));

                  bytes  = CryptoJS.AES.decrypt(userInfo.email, 'secret key 123');
                 var decryptedEmail = JSON.parse(bytes.toString(CryptoJS.enc.Utf8));

                 let userObj={
                    "Full Name":decryptedName,
                    "Email":decryptedEmail,
                    "Phone Number":decryptedNumber
                 }

                 res.send(userObj)

            }

        } catch (error) {

            console.log("Error fetching userData");
        }
        

            // Decrypt
        // var bytes  = CryptoJS.AES.decrypt(ciphertext, 'secret key 123');
        // var decryptedData = JSON.parse(bytes.toString(CryptoJS.enc.Utf8));

        // console.log(decryptedData);

        res.send("user data fetched successfully!!",email,password)
        }

}


let resetPass=async (req,res)=>{
    let {oldPassword,newPassword}=req.body;
    console.log(oldPassword,newPassword);

    if(oldPassword==undefined){
        if(newPassword==undefined){
            res.send("Invalid input,please enter oldPassword and newPassword ro reset")
        }
    }

    if(oldPassword==undefined||newPassword==undefined){
        res.send("Password missing ,please enter valid input")
    }

    let token = req.cookies.jwt
    console.log("token",token);
        if(token){
        let userdata = jwt.verify(token,'jwtKey')
        let { email, password } = userdata;

        console.log("line 166",email,password);

        let hashOldPassword = await bcrypt.hash(oldPassword, salt)
        console.log("hashOldPassword",hashOldPassword,"password",password,"ln 169");
        


        if(password===hashOldPassword){

            console.log("line 175 ,password is matched");

            let hashNewPassword=await bcrypt.hash(newPassword, salt)

            console.log(hashNewPassword,"line 179");

            let result= await userCollection.updateOne({password},{$set:{'password':hashNewPassword}});
            console.log(result,"ln 182");

            let userPayload = { email:email, password:hashNewPassword };
            console.log("userPayload,line 185",userPayload);

            
            // console.log(userPayload);
            let token = jwt.sign(userPayload,'jwtKey', { expiresIn: '1d' })

            console.log(token,"token, line 191");
            // console.log(token);
            res.cookie('jwt', token)

            // // console.log(userPayload);
            // let token = jwt.sign(userPayload,'jwtKey', { expiresIn: '1d' })
            // // console.log(token);
            // res.cookie('jwt', token)

            res.send("Password reset successfull!!")
        }

        else{
            console.log("invalid password");
            res.send("Invalid password")
            }
    }
    else{
        res.send("Error login")
    }
        
}


let editUser=async(req,res)=>{

    let {fname,phNum,email}=req.body;

    if(fname==undefined){
        if(phNum==undefined){
            if(email==undefined){
                res.send("Invalid Input,please add a valid input")
            }
            
        }
    }
    

    let token = req.cookies.jwt
    if(token){
    let userdata = jwt.verify(token,'jwtKey')
    let { password } = userdata;
    console.log(password);

    // var bytes  = CryptoJS.AES.decrypt(userdata.email, 'secret key 123');
    //  decryptedEmail = JSON.parse(bytes.toString(CryptoJS.enc.Utf8));
    
    // if((fname!=undefined)&&(phNum!=undefined)&&(email!=undefined)){

    //     //update name

    //     var encFName = CryptoJS.AES.encrypt(fname, 'secret key 123').toString();
    //     console.log("encFName line 243",encFName);
    //     let resultName= await userCollection.updateOne({"password":password},{$set:{'name':encFName}});
    //     console.log("line 245,resultName",resultName);


    //     //update phNum

    //     var encPhNum = CryptoJS.AES.encrypt(phNum, 'secret key 123').toString();
    //     console.log("encPhNum line 245",encPhNum);
    //     let resultNum= await userCollection.updateOne({"password":password},{$set:{'number':encPhNum}});
    //     console.log("line 253,resultNum",resultNum);


    //     //update email

    //     var encEmail = CryptoJS.AES.encrypt(email, 'secret key 123').toString();
    //     console.log("encEmail line 260",email);
    //     let resultEmail= await userCollection.updateOne({"password":password},{$set:{'email':encEmail}});
    //     console.log("line 261,resultEmail",resultEmail);

    //     res.send("Email,Phone number and Name have been updated successfully!")
        
    // }


    if(fname!=undefined){
        
        var encFName = CryptoJS.AES.encrypt(fname, 'secret key 123').toString();
        console.log("encFName line 281",encFName);
        let result= await userCollection.updateOne({"password":password},{$set:{'name':encFName}});
        console.log("line 283",result);
       // res.send("User name update successfull!")

        }

    if(phNum!=undefined){
        
        var encPhNum = CryptoJS.AES.encrypt(phNum, 'secret key 123').toString();
        console.log("encPhNum line 291",encPhNum);
        let result= await userCollection.updateOne({"password":password},{$set:{'number':encPhNum}});
    
       // res.send("Phone number update successfull!")

            }
    if(email!=undefined){

        var encEmail = CryptoJS.AES.encrypt(email, 'secret key 123').toString();
        console.log("encEmail line 300",encEmail);
        let result= await userCollection.updateOne({"password":password},{$set:{'email':encEmail}});
    
        //res.send("Email updated successfully!")

            }
            res.send("User details updated successfull!")
    }

}

module.exports={
    signup,
    login,
    user,
    logout,
    resetPass,
    editUser
}




// var CryptoJS = require("crypto-js");

// var data = [{id: 1}, {id: 2}]

// // Encrypt
// var ciphertext = CryptoJS.AES.encrypt(JSON.stringify(data), 'secret key 123').toString();

// // Decrypt
// var bytes  = CryptoJS.AES.decrypt(ciphertext, 'secret key 123');
// var decryptedData = JSON.parse(bytes.toString(CryptoJS.enc.Utf8));

// console.log(decryptedData); // [{id: 1}, {id: 2}]




// var CryptoJS = require("crypto-js");

// // Encrypt
// var ciphertext = CryptoJS.AES.encrypt('Veeresh FSD', 'secret key 123').toString();

// // Decrypt
// var bytes  = CryptoJS.AES.decrypt(ciphertext, 'secret key 123');
// var originalText = bytes.toString(CryptoJS.enc.Utf8);

// console.log(originalText); // 'my message'

































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
