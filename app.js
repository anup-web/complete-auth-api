const express = require('express');
const connectDB = require('./config/db');
const authRoutes = require('./routes/authRoutes');
const dotenv = require('dotenv');
const morgan = require('morgan');
const errorHandler = require('./middleware/errorHandler');
const cors = require('cors');
const helmet = require('helmet');
const logger = require('./utils/logger');
const limiter = require('./middleware/rateLimiter');
const { swaggerUi, specs } = require('./utils/swagger');

dotenv.config();
const app = express();
connectDB();

app.use(express.json());
app.use(morgan('dev'));
app.use(errorHandler);
app.use('/api/auth', authRoutes);
app.use(helmet());

app.use(
    cors({
      origin: 'http://your-frontend-domain.com',
      methods: ['GET', 'POST', 'PUT', 'DELETE'],
      credentials: true,
    })
  );

app.use(limiter);

// Serve Swagger UI
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(specs));

  logger.info('Server started on port 5000');
  logger.error('Something went wrong!');  

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));