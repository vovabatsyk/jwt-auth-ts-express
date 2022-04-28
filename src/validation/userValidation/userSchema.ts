import Joi from "joi"

export const userSchema = {
  signupUser: Joi.object({
    name: Joi.string().required(),
    email: Joi.string().email().required(),
    password: Joi.string().required()
  }),
  signinUser: Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string().required()
  }),
  sendVerificationMail: Joi.object({
    email: Joi.string().email().required(),
  }),
  verifyUserMail: Joi.object({
    token: Joi.string().email().required(),
  }),
  sendForgotPasswordMail: Joi.object({
    email: Joi.string().email().required(),
  }),
  verifyForgotPasswordMail: Joi.object({
    token: Joi.string().email().required(),
    password: Joi.string().required()
  }),
}
