
require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const mysql = require('mysql2');
const cookieParser = require('cookie-parser');
const { CognitoIdentityProviderClient, SignUpCommand, InitiateAuthCommand, ConfirmSignUpCommand } = require('@aws-sdk/client-cognito-identity-provider');
const { getDatabaseCredentials } = require('./secretmanager');
const { SQSClient, SendMessageCommand } = require('@aws-sdk/client-sqs');
const jwksClient = require('jwks-rsa');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { S3Client, PutObjectCommand } = require('@aws-sdk/client-s3');

const app = express();
const cognitoClient = new CognitoIdentityProviderClient({ region: process.env.AWS_REGION });
const sqsClient = new SQSClient({ region: process.env.AWS_REGION });
const s3Client = new S3Client({ region: process.env.AWS_REGION });
const QUEUE_URL = process.env.SQS_QUEUE_URL;
const S3_BUCKET = process.env.S3_BUCKET;

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(cookieParser());

// JWT verification function
const client = jwksClient({
    jwksUri: `https://cognito-idp.${process.env.AWS_REGION}.amazonaws.com/${process.env.COGNITO_USER_POOL_ID}/.well-known/jwks.json`
});

function verifyToken(req, res, next) {
    const token = req.cookies.idToken;
    if (!token) return res.redirect('/login');

    const getKey = (header, callback) => {
        client.getSigningKey(header.kid, (err, key) => {
            if (err) return res.status(500).send('Failed to retrieve signing key');
            const signingKey = key.publicKey || key.rsaPublicKey;
            callback(null, signingKey);
        });
    };

    jwt.verify(token, getKey, { algorithms: ['RS256'] }, (err, decoded) => {
        if (err) {
            console.error('Token verification failed:', err);
            return res.redirect('/login');
        }
        req.username = decoded.username;
        next();
    });
}

// Initialize MySQL database
let db;
(async () => {
    const dbCredentials = await getDatabaseCredentials();
    db = mysql.createPool({
        host: process.env.RDS_HOST,
        user: dbCredentials.username,
        password: dbCredentials.password,
        database: process.env.RDS_DATABASE,
        port: process.env.RDS_PORT
    });
})();

// User registration route
app.post('/register', async (req, res) => {
    const { username, password, email } = req.body;
    try {
        const signUpCommand = new SignUpCommand({
            ClientId: process.env.COGNITO_CLIENT_ID,
            Username: username,
            Password: password,
            UserAttributes: [{ Name: 'email', Value: email }]
        });
        await cognitoClient.send(signUpCommand);
        res.redirect(`/verify?username=${encodeURIComponent(username)}`);
    } catch (err) {
        console.error('Registration failed:', err);
        res.status(400).json({ success: false, message: 'Registration failed, please try again' });
    }
});

// Email verification route
app.post('/verify', async (req, res) => {
    const { username, verificationCode } = req.body;
    try {
        const confirmSignUpCommand = new ConfirmSignUpCommand({
            ClientId: process.env.COGNITO_CLIENT_ID,
            Username: username,
            ConfirmationCode: verificationCode
        });
        await cognitoClient.send(confirmSignUpCommand);
        res.json({ success: true, message: 'Verification successful, you can now log in' });
    } catch (err) {
        console.error('Verification failed:', err);
        res.status(400).json({ success: false, message: 'Verification failed, please try again' });
    }
});

// User login route
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const authCommand = new InitiateAuthCommand({
            AuthFlow: 'USER_PASSWORD_AUTH',
            ClientId: process.env.COGNITO_CLIENT_ID,
            AuthParameters: {
                USERNAME: username,
                PASSWORD: password,
            }
        });
        const response = await cognitoClient.send(authCommand);
        const token = response.AuthenticationResult.AccessToken;

        res.cookie('idToken', token, { httpOnly: true, maxAge: 3600000, path: '/' });
        res.json({ success: true, message: 'Login successful' });
    } catch (err) {
        console.error('Login failed:', err);
        res.status(400).json({ success: false, message: 'Invalid username or password' });
    }
});

// Upload image and send SQS message
app.post('/upload', verifyToken, upload.single('file'), async (req, res) => {
    try {
        const format = req.body.format || 'jpg';
        
        // Upload the file to S3
        const fileStream = fs.createReadStream(req.file.path);
        const s3Key = `${req.username}/${req.file.filename}-${Date.now()}.${format}`;

        await s3Client.send(new PutObjectCommand({
            Bucket: S3_BUCKET,
            Key: s3Key,
            Body: fileStream
        }));

        fs.unlinkSync(req.file.path);  // 删除本地上传的文件

        // Send a message to SQS with image processing task details
        const messageBody = {
            username: req.username,
            format: format,
            s3Key: s3Key
        };

        await sqsClient.send(new SendMessageCommand({
            QueueUrl: QUEUE_URL,
            MessageBody: JSON.stringify(messageBody)
        }));

        res.status(200).json({ message: 'Image uploaded and processing request sent' });
    } catch (error) {
        console.error('Error processing upload:', error);
        res.status(500).send('Error processing image upload');
    }
});


// Retrieve user's uploaded files
app.get('/api/files', verifyToken, async (req, res) => {
    const sql = `SELECT file_name, upload_time FROM uploads WHERE username = ? ORDER BY upload_time DESC`;
    db.query(sql, [req.username], (err, results) => {
        if (err) {
            console.error('Error fetching upload history:', err);
            return res.status(500).json({ error: 'Failed to load upload history' });
        }
        res.json(results);
    });
});

// Logout route
app.get('/logout', (req, res) => {
    res.clearCookie('idToken');
    res.redirect('/login');
});

const server = app.listen(80, '0.0.0.0', () => {
    console.log('API Service is running on port 80');
});
