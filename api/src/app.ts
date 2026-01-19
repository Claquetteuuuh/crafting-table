import express from 'express';
import apiRoutes from './routes/api.routes';
import cors from "cors";

const app = express();
const port = 3001;

app.use(cors({
    origin: [
        "http://localhost:3000",
        "*"
    ],
    credentials: true
}));

app.use(express.json());

app.use('/', apiRoutes);

app.listen(port, () => {
    console.log(`Crafting Table API (TypeScript) listening at http://localhost:${port}`);
});
