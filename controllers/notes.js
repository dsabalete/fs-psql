const router = require('express').Router()
const jwt = require('jsonwebtoken')
const { Op } = require('sequelize')
const { SECRET } = require('../util/config')
const { Note, User } = require('../models')

const noteFinder = async (req, res, next) => {
    req.note = await Note.findByPk(req.params.id)
    if (!req.note) {
        return res.status(404).end()
    }
    next()
}

const tokenExtractor = (req, res, next) => {
    const authorization = req.get('authorization')
    if (authorization && authorization.toLowerCase().startsWith('bearer ')) {
        try {
            req.decodedToken = jwt.verify(authorization.substring(7), SECRET)
        } catch {
            return res.status(401).json({ error: 'token invalid' })
        }
    } else {
        return res.status(401).json({ error: 'token missing' })
    }
    next()
}

router.get('/', async (req, res) => {
    const where = {}

    if (req.query.important) {
        where.important = req.query.important === "true"
    }

    if (req.query.search) {
        where.content = {
            [Op.substring]: req.query.search
        }
    }

    const notes = await Note.findAll({
        attributes: { exclude: ['userId'] },
        include: {
            model: User,
            attributes: ['name']
        },
        where
    })
    res.json(notes)
})

router.post('/', tokenExtractor, async (req, res) => {
    try {
        const user = await User.findByPk(req.decodedToken.id)
        const note = await Note.create({ ...req.body, userId: user.id, date: new Date() })
        res.json(note)
    } catch (error) {
        return res.status(400).json({ error })
    }
})

router.get('/:id', noteFinder, async (req, res) => {
    res.json(req.note)
})

router.put('/:id', noteFinder, async (req, res) => {
    req.note.important = req.body.important
    await req.note.save()
    res.json(req.note)
})

router.delete('/:id', noteFinder, async (req, res) => {
    await req.note.destroy()
    res.status(204).end()
})

module.exports = router