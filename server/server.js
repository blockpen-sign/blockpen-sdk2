// server.ts - BlockPen SDK Server

import express from 'express';
import { PrismaClient } from '@prisma/client';
import bodyParser from 'body-parser';
import cors from 'cors';

const prisma = new PrismaClient();
const app = express();

// Middleware
app.use(bodyParser.json());
app.use(cors());

// Routes

// Upload a document
app.post('/documents', async (req, res) => {
    try {
        const { name, content } = req.body;
        const document = await prisma.document.create({
            data: { name, content },
        });
        res.status(201).json(document);
    } catch (error) {
        res.status(500).json({ error: 'Error uploading document' });
    }
});

// Get all documents
app.get('/documents', async (req, res) => {
    try {
        const documents = await prisma.document.findMany();
        res.status(200).json(documents);
    } catch (error) {
        res.status(500).json({ error: 'Error fetching documents' });
    }
});

// Verify a document
app.post('/documents/verify', async (req, res) => {
    try {
        const { id, hash } = req.body;
        const document = await prisma.document.findUnique({ where: { id } });
        if (!document) {
            return res.status(404).json({ error: 'Document not found' });
        }
        const isValid = document.hash === hash;
        res.status(200).json({ isValid });
    } catch (error) {
        res.status(500).json({ error: 'Error verifying document' });
    }
});

// Delete a document
app.delete('/documents/:id', async (req, res) => {
    try {
        const { id } = req.params;
        await prisma.document.delete({ where: { id } });
        res.status(204).send();
    } catch (error) {
        res.status(500).json({ error: 'Error deleting document' });
    }
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});

