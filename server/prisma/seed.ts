// seed.ts - Seed script for the BlockPen SDK Server

import { PrismaClient } from "@prisma/client";
import bcrypt from "bcrypt";
import { v4 as uuidv4 } from "uuid";

const prisma = new PrismaClient();

async function main() {
    console.log("Seeding database...");

    // Hash a password
    const hashedPassword = await bcrypt.hash("password123", 10);

    // Create a user
    const user = await prisma.user.create({
        data: {
            email: "user@example.com",
            password: hashedPassword,
            name: "John Doe",
        },
    });
    console.log("Created user:", user);

    // Create an API key for the user
    const apiKey = await prisma.apiKey.create({
        data: {
            key: uuidv4(),
            userId: user.id,
            usageLimit: 1000,
        },
    });
    console.log("Created API key:", apiKey);

    // Create a document
    const document = await prisma.document.create({
        data: {
            name: "Sample Document",
            content: "This is a sample document content.",
            creatorId: user.id,
            hash: "samplehash123",
        },
    });
    console.log("Created document:", document);

    // Add signers to the document
    const signer = await prisma.documentSigner.create({
        data: {
            documentId: document.id,
            userId: user.id,
            role: "Approver",
        },
    });
    console.log("Added signer:", signer);

    // Add coordinates for the signature block
    const coordinate = await prisma.coordinate.create({
        data: {
            documentId: document.id,
            x: 50,
            y: 100,
            width: 200,
            height: 50,
        },
    });
    console.log("Added coordinate:", coordinate);

    console.log("Seeding completed.");
}

main()
    .catch((e) => {
        console.error(e);
        process.exit(1);
    })
    .finally(async () => {
        await prisma.$disconnect();
    });
