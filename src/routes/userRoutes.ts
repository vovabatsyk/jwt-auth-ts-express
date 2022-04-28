import { signupUserValidation, signinUserValidation, sendVerificationMailValidation, verifyUserMailValidation, verifyForgotPasswordMailValidation, sendForgotPasswordMailValidation } from './../validation/userValidation/userValidation'
import { signupUser, signinUser, sendVerificationMail, verifyUserMail, sendForgotPasswordMail, verifyForgotPasswordMail } from './../controllers/usersControllers'
import { Router } from "express"

const router = Router()

router.post('/signup', signupUserValidation, signupUser)
router.post('/signin', signinUserValidation, signinUser)

router.post('/send-verification-mail', sendVerificationMailValidation, sendVerificationMail)
router.post('/verify-user-mail', verifyUserMailValidation, verifyUserMail)
router.post('/verify-forgot-mail', verifyForgotPasswordMailValidation, verifyForgotPasswordMail)
router.post('/forgot-password', sendForgotPasswordMailValidation, sendForgotPasswordMail)

export default router