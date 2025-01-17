"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.sql = exports.kyselyPrisma = exports.prisma = void 0;
var client_1 = require("@prisma/client");
var kysely_1 = require("kysely");
var prisma_extension_kysely_1 = require("prisma-extension-kysely");
var helper_1 = require("./helper");
var remember_1 = require("./utils/remember");
exports.prisma = (0, remember_1.remember)('prisma', function () {
    return new client_1.PrismaClient({
        datasourceUrl: (0, helper_1.getDatabaseUrl)(),
    });
});
exports.kyselyPrisma = (0, remember_1.remember)('kyselyPrisma', function () {
    return exports.prisma.$extends((0, prisma_extension_kysely_1.default)({
        kysely: function (driver) {
            return new kysely_1.Kysely({
                dialect: {
                    createAdapter: function () { return new kysely_1.PostgresAdapter(); },
                    createDriver: function () { return driver; },
                    createIntrospector: function (db) { return new kysely_1.PostgresIntrospector(db); },
                    createQueryCompiler: function () { return new kysely_1.PostgresQueryCompiler(); },
                },
            });
        },
    }));
});
var kysely_2 = require("kysely");
Object.defineProperty(exports, "sql", { enumerable: true, get: function () { return kysely_2.sql; } });
