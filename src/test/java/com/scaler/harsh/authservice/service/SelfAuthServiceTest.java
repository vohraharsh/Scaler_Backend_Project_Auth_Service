package com.scaler.harsh.authservice.service;

import com.scaler.harsh.authservice.dto.LoginRequestDTO;
import com.scaler.harsh.authservice.dto.LoginResponseDTO;
import com.scaler.harsh.authservice.dto.UserVerifyResponseDTO;
import com.scaler.harsh.authservice.dto.VerifyCredentialsRequestDTO;
import com.scaler.harsh.authservice.exceptions.ServiceException;
import com.scaler.harsh.authservice.security.JwtUtil;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestTemplate;

import java.time.Duration;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class SelfAuthServiceTest {

    private static final String VERIFY_URL = "http://localhost:8081/users/verify-credentials";
    private static final String REVOKED_TOKEN_PREFIX = "revoked-token:";

    @Mock
    private RestTemplate restTemplate;

    @Mock
    private JwtUtil jwtUtil;

    @Mock
    private StringRedisTemplate redisTemplate;

    @Mock
    private ValueOperations<String, String> valueOperations;

    private SelfAuthService selfAuthService;

    @BeforeEach
    void setUp() {
        selfAuthService = new SelfAuthService(restTemplate, jwtUtil, redisTemplate);
        // Only the logout tests actually call opsForValue(); stubbing it here instead of per-test
        // keeps those tests shorter. Harmless for the login tests, which never touch redisTemplate.
        lenient().when(redisTemplate.opsForValue()).thenReturn(valueOperations);
    }

    private LoginRequestDTO loginRequest(String username, String password) {
        LoginRequestDTO request = new LoginRequestDTO();
        request.setUsername(username);
        request.setPassword(password);
        return request;
    }

    private UserVerifyResponseDTO userVerifyResponse(Integer id, String username, String email) {
        UserVerifyResponseDTO dto = new UserVerifyResponseDTO();
        dto.setId(id);
        dto.setUsername(username);
        dto.setEmail(email);
        return dto;
    }

    @Test
    void login_validCredentials_returnsTokenAndUserInfo() {
        UserVerifyResponseDTO userResponse = userVerifyResponse(7, "alice", "alice@example.com");
        when(restTemplate.postForObject(eq(VERIFY_URL), any(VerifyCredentialsRequestDTO.class),
                eq(UserVerifyResponseDTO.class))).thenReturn(userResponse);
        when(jwtUtil.generateToken(7, "alice", "alice@example.com")).thenReturn("signed.jwt.token");

        LoginResponseDTO result = selfAuthService.login(loginRequest("alice", "correctPassword"));

        assertEquals("signed.jwt.token", result.getToken());
        assertEquals(7, result.getUserId());
        assertEquals("alice", result.getUsername());
        assertEquals("alice@example.com", result.getEmail());
    }

    @Test
    void login_forwardsUsernameAndPasswordToUserService() {
        UserVerifyResponseDTO userResponse = userVerifyResponse(7, "alice", "alice@example.com");
        when(restTemplate.postForObject(eq(VERIFY_URL), any(VerifyCredentialsRequestDTO.class),
                eq(UserVerifyResponseDTO.class))).thenReturn(userResponse);
        when(jwtUtil.generateToken(any(), any(), any())).thenReturn("signed.jwt.token");

        selfAuthService.login(loginRequest("alice", "correctPassword"));

        ArgumentCaptor<VerifyCredentialsRequestDTO> captor = ArgumentCaptor.forClass(VerifyCredentialsRequestDTO.class);
        verify(restTemplate).postForObject(eq(VERIFY_URL), captor.capture(), eq(UserVerifyResponseDTO.class));
        assertEquals("alice", captor.getValue().getUsername());
        assertEquals("correctPassword", captor.getValue().getPassword());
    }

    @Test
    void login_userServiceReturns401_throws401WithGenericMessage() {
        HttpClientErrorException unauthorized = HttpClientErrorException.create(
                HttpStatus.UNAUTHORIZED, "Unauthorized", HttpHeaders.EMPTY, new byte[0], null);
        when(restTemplate.postForObject(eq(VERIFY_URL), any(VerifyCredentialsRequestDTO.class),
                eq(UserVerifyResponseDTO.class))).thenThrow(unauthorized);

        ServiceException ex = assertThrows(ServiceException.class,
                () -> selfAuthService.login(loginRequest("alice", "wrongPassword")));
        assertEquals(HttpStatus.UNAUTHORIZED, ex.getStatus());
        assertEquals("Invalid username or password", ex.getMessage());
        verifyNoInteractions(jwtUtil);
    }

    @Test
    void login_userServiceUnreachable_throws503() {
        when(restTemplate.postForObject(eq(VERIFY_URL), any(VerifyCredentialsRequestDTO.class),
                eq(UserVerifyResponseDTO.class))).thenThrow(new ResourceAccessException("Connection refused"));

        ServiceException ex = assertThrows(ServiceException.class,
                () -> selfAuthService.login(loginRequest("alice", "anyPassword")));
        assertEquals(HttpStatus.SERVICE_UNAVAILABLE, ex.getStatus());
        assertEquals("Could not reach User Service", ex.getMessage());
        verifyNoInteractions(jwtUtil);
    }

    @Test
    void login_userServiceReturnsNullBody_throws401() {
        when(restTemplate.postForObject(eq(VERIFY_URL), any(VerifyCredentialsRequestDTO.class),
                eq(UserVerifyResponseDTO.class))).thenReturn(null);

        ServiceException ex = assertThrows(ServiceException.class,
                () -> selfAuthService.login(loginRequest("alice", "anyPassword")));
        assertEquals(HttpStatus.UNAUTHORIZED, ex.getStatus());
        assertEquals("Invalid username or password", ex.getMessage());
        verifyNoInteractions(jwtUtil);
    }

    // ---------- logout (gap #4) ----------

    @Test
    void logout_missingHeader_throws400() {
        ServiceException ex = assertThrows(ServiceException.class, () -> selfAuthService.logout(null));
        assertEquals(HttpStatus.BAD_REQUEST, ex.getStatus());
        verifyNoInteractions(jwtUtil);
        verifyNoInteractions(redisTemplate);
    }

    @Test
    void logout_headerWithoutBearerPrefix_throws400() {
        ServiceException ex = assertThrows(ServiceException.class,
                () -> selfAuthService.logout("sometoken"));
        assertEquals(HttpStatus.BAD_REQUEST, ex.getStatus());
        verifyNoInteractions(jwtUtil);
    }

    @Test
    void logout_validToken_storesInRedisWithRemainingTtl() {
        when(jwtUtil.getExpiration("good.jwt.token"))
                .thenReturn(new Date(System.currentTimeMillis() + 60_000));

        selfAuthService.logout("Bearer good.jwt.token");

        ArgumentCaptor<Duration> ttlCaptor = ArgumentCaptor.forClass(Duration.class);
        verify(valueOperations).set(eq(REVOKED_TOKEN_PREFIX + "good.jwt.token"), eq("1"), ttlCaptor.capture());
        // Allow a little slack for real clock time elapsing between stubbing and assertion.
        assertTrue(ttlCaptor.getValue().toMillis() > 55_000 && ttlCaptor.getValue().toMillis() <= 60_000);
    }

    @Test
    void logout_alreadyExpiredToken_noOp_doesNotTouchRedis() {
        when(jwtUtil.getExpiration("expired.jwt.token")).thenThrow(
                new ExpiredJwtException(null, null, "expired"));

        assertDoesNotThrow(() -> selfAuthService.logout("Bearer expired.jwt.token"));
        verifyNoInteractions(redisTemplate);
    }

    @Test
    void logout_malformedToken_throws401_doesNotTouchRedis() {
        when(jwtUtil.getExpiration("not-a-real-jwt")).thenThrow(
                new MalformedJwtException("malformed"));

        ServiceException ex = assertThrows(ServiceException.class,
                () -> selfAuthService.logout("Bearer not-a-real-jwt"));
        assertEquals(HttpStatus.UNAUTHORIZED, ex.getStatus());
        verifyNoInteractions(redisTemplate);
    }
}