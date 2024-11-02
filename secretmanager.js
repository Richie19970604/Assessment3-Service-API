const { SecretsManagerClient, GetSecretValueCommand } = require('@aws-sdk/client-secrets-manager');

async function getDatabaseCredentials() {
    console.log("Starting to fetch database credentials...");

    const secretsManagerClient = new SecretsManagerClient({ region: 'ap-southeast-2' });
    const secretName = "arn:aws:secretsmanager:ap-southeast-2:901444280953:secret:rds!db-9d0c8c43-82d2-4f0e-8b47-5b29cc073470-wCu4NC";

    try {
        console.log("Sending GetSecretValueCommand for secret:", secretName);
        const command = new GetSecretValueCommand({ SecretId: secretName });
        const response = await secretsManagerClient.send(command);

        if ('SecretString' in response) {
            const secret = JSON.parse(response.SecretString);
            console.log("Secrets Manager fetched successfully.");
            return { username: secret.username, password: secret.password };
        } else {
            throw new Error("Secret value is not a string");
        }
    } catch (err) {
        console.error("Error fetching secret from Secrets Manager:", err);
        throw err; // Exit or handle the error as necessary
    }
}

module.exports = { getDatabaseCredentials };

// Call the function to test it directly in this file
getDatabaseCredentials().then(credentials => {
    console.log("Fetched credentials:", credentials);
}).catch(err => {
    console.error("Failed to fetch credentials:", err);
});
