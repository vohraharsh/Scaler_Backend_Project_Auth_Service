package com.scaler.harsh.authservice.service;

import com.scaler.harsh.authservice.dto.LoginRequestDTO;
import com.scaler.harsh.authservice.dto.LoginResponseDTO;
import com.scaler.harsh.authservice.exceptions.ServiceException;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

@Service
public class FakeStoreAuthService implements AuthService {

    private final RestTemplate restTemplate;

    public FakeStoreAuthService(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    @Override
    public LoginResponseDTO login(LoginRequestDTO request) {
        LoginResponseDTO response;

        try {
            response = restTemplate.postForObject(
                    "https://fakestoreapi.com/auth/login", request, LoginResponseDTO.class);
        } catch (HttpClientErrorException e) {
            throw new ServiceException("Invalid username or password", HttpStatus.UNAUTHORIZED);
        } catch (RestClientException e) {
            throw new ServiceException("Could not reach FakeStoreAPI", HttpStatus.SERVICE_UNAVAILABLE);
        }

        if (response == null || response.getToken() == null) {
            throw new ServiceException("Login failed", HttpStatus.UNAUTHORIZED);
        }

        return response;
    }
}