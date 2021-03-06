import dotenv from "dotenv"
import nodemailer from 'nodemailer'

dotenv.config();

export const DB = process.env.DB!
export const PORT = parseInt(process.env.PORT!)
export const JWT_KEY = process.env.JWT_KEY
export const FRONTEND_URL = process.env.FRONTEND_URL

let testAccount = {
    user: "neu2cxnj2agzrppd@ethereal.email",
    pass: "wJ9hQ8MtBxce6haTk7",
}

export let transporter = nodemailer.createTransport({
    host: "smtp.ethereal.email",
    port: 587,
    secure: false, // true for 465, false for other ports
    auth: {
        user: testAccount.user, // generated ethereal user
        pass: testAccount.pass, // generated ethereal password
    },
})