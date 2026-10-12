package com.anurag.cs;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import javax.crypto.SecretKey;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
@Service
public class JwtService {
    private final SecretKey key;
    public JwtService(@Value("${app.jwt-secret}") String secret) {
        if(secret.getBytes(StandardCharsets.UTF_8).length<32) throw new IllegalArgumentException("JWT_SECRET must contain at least 32 bytes.");
        key=Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
    }
    public String generate(AppUser u) {
        Instant now=Instant.now();
        return Jwts.builder().subject(u.id.toString()).claim("role",u.role.name()).issuer("cybershield").issuedAt(Date.from(now)).expiration(Date.from(now.plusSeconds(28800))).signWith(key).compact();
    }
    public Long userId(String token) {
        return Long.valueOf(Jwts.parser().verifyWith(key).requireIssuer("cybershield").build().parseSignedClaims(token).getPayload().getSubject());
    }
}
