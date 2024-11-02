// app.js - Service A
require('dotenv').config();
const express = require('express');
const axios = require('axios');
const querystring = require('querystring');
const bodyParser = require('body-parser');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const jwt = require('jsonwebtoken');
const { S3Client, PutObjectCommand, GetObjectCommand } = require('@aws-sdk/client-s3');
const mysql = require('mysql2');
const { getSignedUrl } = require('@aws-sdk/s3-request-presigner');
const { CognitoIdentityProviderClient, SignUpCommand, InitiateAuthCommand, ConfirmSignUpCommand } = require('@aws-sdk/client-cognito-identity-provider');
const cookieParser = require('cookie-parser');
const jwksClient = require('jwks-rsa');
const { SSMClient, GetParameterCommand } = require('@aws-sdk/client-ssm');
const Memcached = require('memcached');
const { SQSClient, SendMessageCommand } = require('@aws-sdk/client-sqs');
const { getDatabaseCredentials } = require('./secretmanager');

const app = express();
const upload = multer({ dest: 'uploads/' });
const memcached = new Memcached('team31.km2jzi.cfg.apse2.cache.amazonaws.com:11211');

// 环境变量
let S3_BUCKET;
let queueUrl = process.env.SQS_QUEUE_URL;
const AWS_REGION = process.env.AWS_REGION;
const userPoolId = process.env.COGNITO_USER_POOL_ID;
const clientId = process.env.COGNITO_CLIENT_ID;
const redirectUri = process.env.GOOGLE_REDIRECT_URI;
const googleClientId = process.env.GOOGLE_CLIENT_ID;
const googleClientSecret = process.env.GOOGLE_CLIENT_SECRET;

// AWS 客户端
const s3Client = new S3Client({ region: AWS_REGION });
const sqsClient = new SQSClient({ region: AWS_REGION });
const cognitoClient = new CognitoIdentityProviderClient({ region: AWS_REGION });

// 数据库初始化
let db;
(async () => {
    try {
        const dbCredentials = await getDatabaseCredentials();
        db = mysql.createPool({
            host: process.env.RDS_HOST,
            user: dbCredentials.username,
            password: dbCredentials.password,
            database: process.env.RDS_DATABASE,
            port: process.env.RDS_PORT
        });

        db.query(`
            CREATE TABLE IF NOT EXISTS uploads (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(255),
                file_name VARCHAR(255),
                upload_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                status VARCHAR(50),
                message TEXT
            )`);
    } catch (err) {
        console.error("Failed to initialize the database connection with Secrets Manager credentials.", err);
        process.exit(1);
    }
})();

// 中间件
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// JWT 客户端
const client = jwksClient({
    jwksUri: `https://cognito-idp.${AWS_REGION}.amazonaws.com/${userPoolId}/.well-known/jwks.json`
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
        if (err) return res.redirect('/login');
        req.username = decoded.username;
        next();
    });
}

// 从 SSM 获取 S3 Bucket 名称
async function getS3BucketName() {
    const ssmClient = new SSMClient({ region: 'ap-southeast-2' });
    const parameterName = '/n10324721/A2_parameter/S3BucketName';

    try {
        const command = new GetParameterCommand({ Name: parameterName });
        const response = await ssmClient.send(command);
        return response.Parameter.Value;
    } catch (error) {
        console.error("Error fetching S3 Bucket Name:", error);
        throw new Error("Failed to fetch S3 Bucket Name");
    }
}

// 初始化 S3 Bucket 名称
(async () => {
    try {
        S3_BUCKET = await getS3BucketName();
    } catch (error) {
        console.error("Failed to initialize S3 bucket name.");
        process.exit(1);
    }
})();

// 文件上传并发送转换任务
app.post('/upload', verifyToken, upload.single('file'), async (req, res) => {
    if (!req.file) return res.status(400).send('No file uploaded');

    const format = req.body.format || 'jpg';
    const fileKey = `${req.username}/${req.file.filename}`;

    const fileStream = fs.createReadStream(req.file.path);
    await s3Client.send(new PutObjectCommand({
        Bucket: S3_BUCKET,
        Key: fileKey,
        Body: fileStream
    }));

    const messageBody = {
        username: req.username,
        fileName: req.file.filename,
        format: format
    };

    await sqsClient.send(new SendMessageCommand({
        QueueUrl: queueUrl,
        MessageBody: JSON.stringify(messageBody),
    }));

    fs.unlinkSync(req.file.path);
    res.redirect('/personal');
});

// 查询文件上传历史
app.get('/api/files', verifyToken, async (req, res) => {
    const cacheKey = `uploads:${req.username}`;
    memcached.get(cacheKey, async (err, data) => {
        if (data) return res.json(JSON.parse(data));

        const sql = `SELECT file_name, upload_time, status, message FROM uploads WHERE username = ? ORDER BY upload_time DESC`;
        db.query(sql, [req.username], async (err, results) => {
            if (err) return res.status(500).json({ error: 'Failed to load upload history' });

            const files = await Promise.all(results.map(async row => {
                const fileKey = `${req.username}/${row.file_name}`;
                const url = await getSignedUrl(s3Client, new GetObjectCommand({
                    Bucket: S3_BUCKET,
                    Key: fileKey,
                }), { expiresIn: 300 });

                return {
                    name: row.file_name,
                    uploadTime: row.upload_time,
                    url,
                    status: row.status,
                    message: row.message
                };
            }));

            memcached.set(cacheKey, JSON.stringify(files), 300);
            res.json(files);
        });
    });
});

// 用户注册
app.post('/register', async (req, res) => {
    const { username, password, email } = req.body;
    try {
        const signUpCommand = new SignUpCommand({
            ClientId: clientId,
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

// 验证页面
app.get('/verify', (req, res) => res.sendFile(path.join(__dirname, 'views', 'verify.html')));

// 验证用户注册
app.post('/verify', async (req, res) => {
    const { username, verificationCode } = req.body;
    try {
        const confirmSignUpCommand = new ConfirmSignUpCommand({
            ClientId: clientId,
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

// 用户登录
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const authCommand = new InitiateAuthCommand({
            AuthFlow: 'USER_PASSWORD_AUTH',
            ClientId: clientId,
            AuthParameters: {
                USERNAME: username,
                PASSWORD: password,
            }
        });
        const response = await cognitoClient.send(authCommand);
        const token = response.AuthenticationResult.AccessToken;

        res.cookie('idToken', token, {
            httpOnly: true,
            maxAge: 3600000,
            path: '/',
        });

        res.json({ success: true, message: 'Login successful' });
    } catch (err) {
        console.error('Login failed:', err);
        res.status(400).json({ success: false, message: 'Invalid username or password' });
    }
});

// 登出
app.get('/logout', (req, res) => {
    res.clearCookie('idToken');
    res.redirect('/login');
});

// Google登录回调
app.get('/callback', async (req, res) => {
    const authorizationCode = req.query.code;

    if (!authorizationCode) {
        return res.status(400).send('Authorization code not provided');
    }

    try {
        const tokenResponse = await axios.post(`https://oauth2.googleapis.com/token`, querystring.stringify({
            grant_type: 'authorization_code',
            client_id: googleClientId,
            client_secret: googleClientSecret,
            code: authorizationCode,
            redirect_uri: redirectUri
        }), {
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            }
        });

        const { id_token, access_token } = tokenResponse.data;

        res.cookie('idToken', id_token, { httpOnly: true });
        res.cookie('accessToken', access_token, { httpOnly: true });
        res.redirect('/personal');
    } catch (err) {
        console.error('Error during Google OAuth callback:', err);
        res.status(500).send('Login failed');
    }
});

// 启动服务器
app.listen(80, () => console.log('Service A running on port 80'));
