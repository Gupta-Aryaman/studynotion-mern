const User = require("../models/User");
const mailSender = require("../utils/mailSender");
const bcrypt = require("bcrypt");


//resetPasswordToken
exports.resetPasswordToken = async (req, res) => {
    try{
        const email = req.body.email;
        const user = await User.findOne({ email });

        if(!user){
            return res.status(400).json({
                success: false,
                message: "User does not exist",
            });
        }

        const token = crypto.randomUUID();

        //class 2 - time 01:40:00 - code is different
        user.token = token;
        user.resetPasswordExpires = Date.now() + 5*60*1000; //5 minutes
        await user.save();

        //create url
        const url = `http://localhost:3000/update-password/${token}`;
        
        //send mail
        await mailSender(email, "Password Reset Link", `Password reset lin: ${url}`);

        return res.status(200).json({
            success: true,
            message: "Password reset link sent to email",
        });
    } catch(error){
        console.log(error);
        return res.status(500).json({
            success: false,
            message: "Internal Server Error in resetPassword",
        });
    }

    
}


//resetPassword
exports.resetPassword = async (req, res) => {
    try{
        //data fetch
        const { password, confirmPassword, token } = req.body;
        //validation
        if(password !== confirmPassword){
            return res.status(400).json({
                success: false,
                message: "Passwords do not match",
            });
        }

        //get userdetails from db using token
        const userDetails = await User.findOne({ token: token });

        //if no entry - invalid token
        if(!userDetails){
            return res.status(400).json({
                success: false,
                message: "Token is invalid",
            });
        }

        //token time check
        if(userDetails.resetPasswordExpires < Date.now()){
            return res.status(400).json({
                success: false,
                message: "Token expired please regenerate your token",
            });
        }

        // hash pwd
        const hashedPassword = await bcrypt.hash(password, 10);

        //password update
        //class 2 - time 01:55:00 - code is different
        userDetails.password = hashedPassword;
        userDetails.token = null;
        userDetails.resetPasswordExpires = null;
        await userDetails.save();

        //return response
        return res.status(200).json({
            success: true,
            message: "Password updated successfully",
        });
        
    } catch(error){
        console.log(error);
        return res.status(500).json({
            success: false,
            message: "Internal Server Error in resetPassword",
        });
    }

};