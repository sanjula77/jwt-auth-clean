const jwt = require('jsonwebtoken');

exports.identifier = (req, res, next) => {
	let token;
	if (req.headers.client === 'not-browser') {
		token = req.headers.authorization;
	} else {
		token = req.cookies['Authorization'];
	}

	if (!token) {
		return res.status(401).json({ success: false, message: 'No token provided' });
	}

	try {
		const userToken = token.split(' ')[1];
		const jwtVerified = jwt.verify(userToken, process.env.TOKEN_SECRET);
		if (jwtVerified) {
			req.user = jwtVerified;
			next();
		} else {
			throw new Error('Invalid token');
		}
	} catch (error) {
		console.log(error);
		if (error.name === 'TokenExpiredError') {
			return res.status(401).json({ 
				success: false, 
				message: 'Token expired',
				isExpired: true
			});
		}
		return res.status(401).json({ 
			success: false, 
			message: 'Invalid token',
			isExpired: false
		});
	}
};