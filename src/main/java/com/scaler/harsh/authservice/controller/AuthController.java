package com.scaler.harsh.authservice.controller;

import com.scaler.harsh.authservice.dto.LoginRequestDTO;
import com.scaler.harsh.authservice.dto.LoginResponseDTO;
import com.scaler.harsh.authservice.exceptions.ServiceException;
import com.scaler.harsh.authservice.service.AuthService;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AuthController {

    private final AuthService svc;

    public AuthController(AuthService svc) {
        this.svc = svc;
    }

    @PostMapping("/auth/login")
    public LoginResponseDTO login(@RequestBody LoginRequestDTO request) {
        if (request.getUsername() == null || request.getUsername().isBlank()) {
            throw new ServiceException("Username cannot be empty", HttpStatus.BAD_REQUEST);
        }
        if (request.getPassword() == null || request.getPassword().isBlank()) {
            throw new ServiceException("Password cannot be empty", HttpStatus.BAD_REQUEST);
        }
        return svc.login(request);
    }
}