const User = require("../models/User");
const OTP = require("../models/OTP");
const Profile = require("../models/Profile");
const OTPgenerator = require("otp-generator");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
require("dotenv").config();

//sendOTP
exports.sendOTP = async (req, res) => {
    
    try{
        //fetch email id from req.body
        const { email } = req.body;

        //check if email exists in DB
        const checkUserPresent = await User.findOne({ email });

        //if email already exists, send error
        if(checkUserPresent){
            return res.status(400).json({ 
                success: false,
                message: "User already exists",
            });
        }

        //generate OTP
        var otp = otpGenerator.generate(6, { 
            upperCase: false, 
            specialChars: false,
            lowerCase: false,
            alphabets: false 
        });
        console.log("OTP generated successfully: ", otp);

        //check unique OTP or not
        let checkOTP = await OTP.findOne({ otp: otp });

        while(checkOTP){
            var otp = otpGenerator.generate(6, { 
                upperCase: false, 
                specialChars: false,
                lowerCase: false,
                alphabets: false 
            });
            checkOTP = await OTP.findOne({ otp: otp });
        }

        //save OTP in DB
        const newOTP = new OTP({
            otp: otp,
            email: email,
        });
        await newOTP.save();

        //return success response
        return res.status(200).json({
            success: true,
            message: "OTP sent successfully",
            otp: otp,
        });

    }
    catch(error){
        console.log("Error occurred while sending OTP: ", error);
        return res.status(500).json({
            success: false,
            message: "Internal Server Error",
        });
    }
};



//signup
exports.signup = async (req, res) => {
    try{
        //data fetch from body
        const { 
            firstName,
            lastName,
            email,
            password,
            confirmPassword,
            accountType,
            contactNumber,
            otp
        } = req.body;
        

        //validate data
        if(!firstName || !lastName || !email || !password || !confirmPassword || !accountType || !contactNumber || !otp){
            return res.status(400).json({
                success: false,
                message: "All fields are required",
            });
        }

        //check if passwords match
        if(password !== confirmPassword){
            return res.status(400).json({
                success: false,
                message: "Passwords do not match",
            });
        }

        //check if user already exists
        const checkUser = await User.findOne({ email });
        if(checkUser){
            return res.status(400).json({
                success: false,
                message: "User already exists",
            });
        }

        //find most recent otp for the user
        const recentOTP = await OTP.findOne({ email }).sort({ createdAt: -1 }).limit(1);
        console.log(recentOTP);

        //validateOTP
        if(recentOTP.length == 0){
            //no otp found
            return res.status(400).json({
                success: false,
                message: "OTP not found",
            });
        }
        else if(otp !== recentOTP.otp){
            //invalid OTP
            return res.status(400).json({
                success: false,
                message: "Invalid OTP",
            });
        }

        //hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        //create new user
        const profileDetails = await Profile.create({
            gender: null,
            dob: null,
            about: null,
            contactNumber: null,
        });

        const user = await User.create({
            firstName: firstName,
            lastName: lastName,
            email: email,
            contactNumber: contactNumber,
            password: hashedPassword,
            accountType: accountType,
            additionalDetails: profileDetails._id,
            image: `https://api.dicebear.com/5.x/initials/svg?seed=${firstName} ${lastName}`,
        });

        //return response
        return res.status(200).json({
            success: true,
            message: "User created successfully",
            user: user,
        });

    }
    catch(error){
        console.log("Error occurred while signing up: ", error);
        return res.status(500).json({
            success: false,
            message: "Internal Server Error",
        });
    }

};



//login
exports.login = async (req, res) => {
    try{
        //fetch data from body
        const { email, password } = req.body;

        //validate data
        if(!email || !password){
            return res.status(400).json({
                success: false,
                message: "All fields are required",
            });
        }

        //check if user exists
        let user = await User.findOne({ email });
        if(!user){
            return res.status(400).json({
                success: false,
                message: "User does not exist, please signup first",
            });
        }

        //check if password is correct
        const isPasswordCorrect = await bcrypt.compare(password, user.password);
        if(!isPasswordCorrect){
            return res.status(401).json({
                success: false,
                message: "Invalid Credentials",
            });
        }

        const payload = {
            user: {
                email: user.email,
                id: user._id,
                role: user.accountType,
            },
        };
        const token = jwt.sign(payload, process.env.JWT_SECRET, 
            { 
                expiresIn: "2h" 
            });
        user.token = token;
        user.password = undefined;

        //create cookie
        const options = {
            expires: new Date(Date.now() + 2 * 24 * 60 * 60 * 1000),
            httpOnly: true,
        };
        res.cookie("token", token, options).status(200).json({
            success: true,
            token: token,
            user: user,
            message: "User logged in successfully",
        })

        // //return response
        // return res.status(200).json({
        //     success: true,
        //     message: "User logged in successfully",
        //     user: user,
        // });
    }
    catch(error){
        console.log("Error occurred while logging in: ", error);
        return res.status(500).json({
            success: false,
            message: "Internal Server Error",
        });
    }
};


//changePassword
exports.changePassword = async (req, res) => {
    //get data from req body
    const { 
        email,
        oldpassword,
        newpassword,
        confirmPassword, 
    } = req.body;

    // get oldpass, newpass, confirmpass
    if(!oldpassword || !newpassword || !confirmpassword || !email){
        return res.status(400).json({
            success: false,
            message: "All fields are required",
        });
    }

    // validate data
    if(oldpassword !== confirmpassword){
        return res.status(400).json({
            success: false,
            message: "Passwords do not match",
        });
    }

    const user = await User.findOne({ email });
    // check if oldpass is correct
    const isPasswordCorrect = await bcrypt.compare(oldpassword, user.password);
    if(!isPasswordCorrect){
        return res.status(401).json({
            success: false,
            message: "Old password is incorrect",
        });
    }

    //update pwd in db
    const hashedPassword = await bcrypt.hash(newpassword, 10);
    user.password = hashedPassword;
    await user.save();

    //send mail password updated
    
    //return response
    return res.status(200).json({
        success: true,
        message: "Password updated successfully",
    });
}