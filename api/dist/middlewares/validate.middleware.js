"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.validateResult = void 0;
const zod_1 = require("zod");
const validateResult = (schema) => (req, res, next) => {
    try {
        req.body = schema.parse(req.body);
        next();
    }
    catch (error) {
        if (error instanceof zod_1.ZodError) {
            return res.status(400).json({
                status: 'error',
                message: 'Validation failed',
                errors: error.errors.map(e => ({
                    field: e.path.join('.'),
                    message: e.message
                }))
            });
        }
        next(error);
    }
};
exports.validateResult = validateResult;
