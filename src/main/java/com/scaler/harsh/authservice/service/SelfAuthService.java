package com.scaler.harsh.authservice.service;

import com.scaler.harsh.authservice.dto.LoginRequestDTO;
import com.scaler.harsh.authservice.dto.LoginResponseDTO;
import com.scaler.harsh.authservice.dto.UserVerifyResponseDTO;
import com.scaler.harsh.authservice.dto.VerifyCredentialsRequestDTO;
import com.scaler.harsh.authservice.exceptions.ServiceException;
import com.scaler.harsh.authservice.security.JwtUtil;
import org.springframework.context.annotation.Primary;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

@Service
@Primary
public class SelfAuthService implements AuthService {

    private static final String USER_SERVICE_URL = "http://localhost:8081";

    private final RestTemplate restTemplate;
    private final JwtUtil jwtUtil;

    public SelfAuthService(RestTemplate restTemplate, JwtUtil jwtUtil) {
        this.restTemplate = restTemplate;
        this.jwtUtil = jwtUtil;
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
}