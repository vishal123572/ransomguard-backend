# RansomGuard Backend

Java 21 and Spring Boot REST API for the Ransomware Detection and File Protection System. It handles authentication, roles, file-check reports, prevention tasks, activity records, and the administrator database view.

## Requirements

- Java 21
- Maven
- MySQL

## Configuration

Set `DATABASE_URL`, `MYSQLUSER`, `MYSQLPASSWORD`, `JWT_SECRET`, and `CORS_ORIGINS` in the environment. For an empty database, also configure `ADMIN_EMAIL`, `ADMIN_PASSWORD` (at least 12 characters), and optionally `ADMIN_NAME` for first startup. Keep real credentials out of source control.

## Run locally

From this directory, run `mvn spring-boot:run`. The default local address is `http://localhost:8080`; the health endpoint is `/api/health`.

## Tests

Run `mvn test`.