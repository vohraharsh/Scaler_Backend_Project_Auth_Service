package com.scaler.harsh.authservice.security;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;

@Component
public class JwtUtil {

    private final SecretKey key;
    private final long expirationMs;

    public JwtUtil(@Value("${jwt.secret}") String secret,
                   @Value("${jwt.expiration-ms}") long expirationMs) {
        this.key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        this.expirationMs = expirationMs;
    }

    public String generateToken(Integer userId, String username, String email) {
        Date now = new Date();
        Date expiry = new Date(now.getTime() + expirationMs);

        return Jwts.builder()
                // Must match a consumer's jwt_secrets[].key in Kong's kong.yml — Kong's jwt plugin
                // looks up which consumer's secret to verify against by this claim (key_claim_name
                // defaults to "iss").
                .issuer("ecommerce-auth-service")
                .subject(String.valueOf(userId))
                .claim("username", username)
                .claim("email", email)
                .issuedAt(now)
                .expiration(expiry)
                // Pin HS256 explicitly. signWith(key) alone lets jjwt auto-pick the strongest HMAC
                // variant the key's byte length supports — our secret is long enough that it silently
                // picked HS384, which doesn't match Kong's jwt_secrets[].algorithm: HS256 and gets
                // rejected with "Invalid algorithm".
                .signWith(key, Jwts.SIG.HS256)
                .compact();
    }
}