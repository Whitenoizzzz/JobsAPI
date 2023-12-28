const mongoose = require('mongoose')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
require('dotenv').config();

const UserSchema = new mongoose.Schema({
    name:{
        type : String,
        required: [true, 'Please provide name'],
        minlength : 3,
        maxlength : 50
    },
    email:{
        type : String,
        required: [true, 'Please provide email'],
        match : [/^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/,
                 'Please provide email id'], //regex for template check of email
        unique : true  //checks if email is unique
    },
    password:{
        type : String,
        required: [true, 'Please provide password'],
        minlength : 6,
    },

}) 
// this is mongoose middleware you can use to modify the properties before saving to the db 
// instead of writing in the controller
UserSchema.pre('save', async function(){
    
    //function for hashing the password
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password,salt)
})
// mongoose allow us something known as instance methods i.e you can create methods for document. 
// better for repetative work like creating token for everyuser
UserSchema.methods.getName = function(){
    return this.name
}
UserSchema.methods.createJWT = function (){
    return jwt.sign({userId: this._id, name: this.name},process.env.JWT_SECRET,{
        expiresIn : process.env.JWT_LIFETIME
    })
}
UserSchema.methods.comparePassword = async function (candidatePassword){
    const isMatch = await bcrypt.compare(candidatePassword,this.password)
    return isMatch
}
module.exports = mongoose.model('User',UserSchema)