'use strict';

const cors        = require('cors');
const express     = require('express');
const morgan      = require('morgan');
const logger      = require('log123').createLogger(''); // logs to console if no filename
const app         = express();
const compression = require('compression');
require('dotenv').config();

const PORT = process.env.PORT;

app.use(
  morgan(process.env.NODE_ENV === 'production' ? 'common' : 'dev', {
    skip: () => process.env.NODE_ENV === 'test'
  })
);

app.use(express.json({limit: '5mb'}));
app.use(express.urlencoded({limit: '5mb', extended: true}));

app.use(compression());

const allowedOrigins = typeof process.env.ALLOWED_ORIGINS  === 'string' ?
  process.env.ALLOWED_ORIGINS.split(',') : [] ;

app.use(
  cors({
    origin: function(origin, callback){
      const _origin = `${origin}`; // this converts undefined to 'undefined' to allow PostMan if .env includes undefined as an origin
      const index = allowedOrigins.indexOf(_origin);
      if(index !== -1){
        callback(null, true);
      } else {
        // eslint-disable-next-line no-console
        console.error(`origin ${origin} blocked`);
        callback(new Error(`origin not allowed by CORS: ${origin}`));
      }
    }
  })
);

let server; 

function runServer(port=PORT) {

  return new Promise(resolve => {
      server = app.listen(port, () => {
				logger.info(`\nAs of ${new Date()}, StormWatch is listening on port ${port}. Mode: ${process.env.NODE_ENV}. Database: ${process.env.DB_MODE}`);
				resolve();
			})
			.on('error', err => {
				logger.error(`Express failed to start ${err}`);
			});
  })
	.then(()=>{
		const { router: authRouter             } = require('./routers/auth');

		app.use('/api/auth' ,               authRouter);

		if(process.env.ENABLE_SCHEDULES === 'true') { // string 'true' is correct
			
			if(process.env.ENABLE_FETCHING === 'true'){
				require('./schedules/fetching');
			}
		}

		console.log('All server modules have loaded. Ready for use. Done.');
		return;
	});
}

// if called directly, vs 'required as module'
if (require.main === module) { // i.e. if server.js is called directly (so indirect calls, such as testing, don't run this)
  runServer().catch(err => logger.error(err));
}

module.exports = { app, runServer };