const express = require('express')
const { login, register } = require('../controller/controller')
const router = new express.Router()
router.post('/login', login)
router.post('/register',register)

module.exports=router