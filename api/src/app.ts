import express from 'express';
import apiRoutes from './routes/api.routes';

const app = express();
const port = 3000;

app.use(express.json());

app.use('/', apiRoutes);

app.listen(port, () => {
    console.log(`MSFVenom API (TypeScript) listening at http://localhost:${port}`);
});
