

let userModel = require('../schemas/users')
let bcrypt = require('bcrypt')

module.exports = {
    CreateAnUser: async function (username, password, email, role,
        avatarUrl, fullName, status, loginCount
    ) {
        let newUser = new userModel({
            username: username,
            password: password,
            email: email,
            role: role,
            avatarUrl: avatarUrl,
            fullName: fullName,
            status: status,
            loginCount: loginCount
        })
        await newUser.save();
        return newUser;
    },
    QueryByUserNameAndPassword: async function (username, password) {
        let getUser = await userModel.findOne({ username: username, isDeleted: false });
        if (!getUser) {
            return false;
        }
        // Compare password with hashed password
        let isPasswordValid = bcrypt.compareSync(password, getUser.password);
        if (!isPasswordValid) {
            return false;
        }
        return getUser;
    },
    FindUserById: async function (id) {
        return await userModel.findOne({
            _id: id,
            isDeleted:false
        }).populate('role')
    },
    ChangePassword: async function (userId, oldPassword, newPassword) {
        let user = await userModel.findOne({ _id: userId, isDeleted: false });
        if (!user) {
            return { success: false, message: "User not found" };
        }
        // Verify old password
        let isOldPasswordValid = bcrypt.compareSync(oldPassword, user.password);
        if (!isOldPasswordValid) {
            return { success: false, message: "Old password is incorrect" };
        }
        // Hash new password and update
        let salt = bcrypt.genSaltSync(10);
        user.password = bcrypt.hashSync(newPassword, salt);
        await user.save();
        return { success: true, message: "Password changed successfully" };
    }
}