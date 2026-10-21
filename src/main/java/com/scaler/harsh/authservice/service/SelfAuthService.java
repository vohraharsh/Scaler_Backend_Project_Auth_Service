package com.scaler.harsh.authservice.service;

import com.scaler.harsh.authservice.dto.LoginRequestDTO;
import com.scaler.harsh.authservice.dto.LoginResponseDTO;
import com.scaler.harsh.authservice.dto.UserVerifyResponseDTO;
import com.scaler.harsh.authservice.dto.VerifyCredentialsRequestDTO;
import com.scaler.harsh.authservice.exceptions.ServiceException;
import com.scaler.harsh.authservice.security.JwtUtil;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import org.springframework.context.annotation.Primary;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import java.time.Duration;
import java.util.Date;

@Service
@Primary
public class SelfAuthService implements AuthService {

    private static final String USER_SERVICE_URL = "http://localhost:8081";

    // Must match the prefix every service's JwtAuthFilter checks against in its own Redis lookup.
    private static final String REVOKED_TOKEN_PREFIX = "revoked-token:";

    private final RestTemplate restTemplate;
    private final JwtUtil jwtUtil;
    private final StringRedisTemplate redisTemplate;

    public SelfAuthService(RestTemplate restTemplate, JwtUtil jwtUtil, StringRedisTemplate redisTemplate) {
        this.restTemplate = restTemplate;
        this.jwtUtil = jwtUtil;
        this.redisTemplate = redisTemplate;
    }

    @Override
    public LoginResponseDTO login(LoginRequestDTO request) {
        VerifyCredentialsRequestDTO verifyRequest = new VerifyCredentialsRequestDTO();
        verifyRequest.setUsername(request.getUsername());
        verifyRequest.setPassword(request.getPassword());

        UserVerifyResponseDTO user;
        try {
            user = restTemplate.postForObject(
                    USER_SERVICE_URL + "/users/verify-credentials",
                    verifyRequest, UserVerifyResponseDTO.class);
        } catch (HttpClientErrorException.Unauthorized e) {
            throw new ServiceException("Invalid username or password", HttpStatus.UNAUTHORIZED);
        } catch (RestClientException e) {
            throw new ServiceException("Could not reach User Service", HttpStatus.SERVICE_UNAVAILABLE);
        }

        if (user == null) {
            throw new ServiceException("Invalid username or password", HttpStatus.UNAUTHORIZED);
        }

        String token = jwtUtil.generateToken(user.getId(), user.getUsername(), user.getEmail());

        LoginResponseDTO response = new LoginResponseDTO();
        response.setToken(token);
        response.setUserId(user.getId());
        response.setUsername(user.getUsername());
        response.setEmail(user.getEmail());
        return response;
    }

    @Override
    public void logout(String authorizationHeader) {
        if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
            throw new ServiceException("Missing or malformed Authorization header", HttpStatus.BAD_REQUEST);
        }

        String token = authorizationHeader.substring(7);

        Date expiration;
        try {
            expiration = jwtUtil.getExpiration(token);
        } catch (ExpiredJwtException e) {
            // Already expired — nothing left to revoke, the end state the caller wants
            // ("this token must not work") is already true. Treat as a successful no-op
            // rather than an error, so a client that double-submits logout isn't punished.
            return;
        } catch (JwtException | IllegalArgumentException e) {
            throw new ServiceException("Invalid token", HttpStatus.UNAUTHORIZED);
        }

        long remainingMs = expiration.getTime() - System.currentTimeMillis();
        if (remainingMs > 0) {
            // TTL = exactly how long the token would have remained valid anyway — never store
            // a revocation entry longer than the token itself could ever have been presented.
            redisTemplate.opsForValue().set(REVOKED_TOKEN_PREFIX + token, "1", Duration.ofMillis(remainingMs));
        }
    }
}