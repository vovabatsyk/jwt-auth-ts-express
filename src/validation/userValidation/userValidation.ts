import { userSchema } from './userSchema'
import { RequestHandler } from "express"
import validator from "../utils/validator"

export const signupUserValidation: RequestHandler = (req, res, next) =>
  validator(userSchema.signupUser, req.body, next)

export const signinUserValidation: RequestHandler = (req, res, next) =>
  validator(userSchema.signinUser, req.body, next)

export const sendVerificationMailValidation: RequestHandler = (req, res, next) =>
  validator(userSchema.sendVerificationMail, req.body, next)

export const verifyUserMailValidation: RequestHandler = (req, res, next) =>
  validator(userSchema.verifyUserMail, req.body, next)

export const sendForgotPasswordMailValidation: RequestHandler = (req, res, next) =>
  validator(userSchema.sendForgotPasswordMail, req.body, next)

export const verifyForgotPasswordMailValidation: RequestHandler = (req, res, next) =>
  validator(userSchema.verifyForgotPasswordMail, req.body, next)
