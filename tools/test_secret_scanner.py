from backend.scanner.secret_scanner import scan_secrets


def print_results(title: str, text: str) -> None:
    print("\n" + "=" * 80)
    print(title)
    print("-" * 80)
    print(text)
    print("-" * 80)

    detections = scan_secrets(text)

    if not detections:
        print("No detections")
        return

    for detection in detections:
        print(detection)


def main() -> None:
    test_cases = [
        (
            "API key",
            'api_key = "abc1234567890SECRETKEY"',
        ),
        (
            "Secret key",
            'secret_key = "my_super_secret_key_123456789"',
        ),
        (
            "Access token",
            'access_token = "access_1234567890abcdefghijklmnop"',
        ),
        (
            "Bearer token",
            "Authorization: Bearer abcdefghijklmnopqrstuvwxyz1234567890",
        ),
        (
            "GitHub token",
            "github token: ghp_abcdefghijklmnopqrstuvwxyz123456",
        ),
        (
            "AWS access key ID",
            "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
        ),
        (
            "JWT token",
            "token = eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature123456789",
        ),
        (
            "Private key",
            "-----BEGIN PRIVATE KEY-----\nabc123\n-----END PRIVATE KEY-----",
        ),        (
            "Database URL",
            'DATABASE_URL="postgresql://dbuser:dbpassword123@localhost:5432/appdb"',
        ),
        (
            "MongoDB URI",
            "MONGO_URI=mongodb+srv://dbuser:dbpassword123@cluster.example.com/appdb",
        ),
        (
            "Redis URI",
            "REDIS_URL=redis://:redispassword123@localhost:6379/0",
        ),
        (
            "Database password",
            "DB_PASSWORD=myDatabasePassword123",
        ),        (
            "Postgres URI",
            "postgres://dbuser:dbpassword123@localhost:5432/appdb",
        ),
        (
            "MySQL URI",
            "mysql://dbuser:dbpassword123@localhost:3306/appdb",
        ),
        (
            "MariaDB URI",
            "mariadb://dbuser:dbpassword123@localhost:3306/appdb",
        ),
        (
            "Clean text",
            "Hello, this is normal text with no secrets.",
        ),
    ]

    for title, text in test_cases:
        print_results(title, text)


if __name__ == "__main__":
    main()