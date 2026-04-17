const { Model, DataTypes } = require('sequelize')
const { sequelize } = require('../util/db')

class User extends Model { }

User.init({
    id: {
        type: DataTypes.INTEGER,
        primaryKey: true,
        autoIncrement: true
    },
    username: {
        type: DataTypes.STRING,
        unique: {
            msg: 'Email address is already in use'
        },
        allowNull: false,
        validate: {
            isEmail: {
                msg: 'Username must be a valid email address'
            }
        }
    },
    name: {
        type: DataTypes.STRING,
        allowNull: false
    },
}, {
    sequelize,
    underscored: true,
    timestamps: false,
    modelName: 'user'
})

module.exports = User