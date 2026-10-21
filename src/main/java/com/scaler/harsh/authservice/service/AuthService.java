package com.scaler.harsh.authservice.service;

import com.scaler.harsh.authservice.dto.LoginRequestDTO;
import com.scaler.harsh.authservice.dto.LoginResponseDTO;

public interface AuthService {
    LoginResponseDTO login(LoginRequestDTO request);

    // Gap #4: revokes the token carried in the raw "Authorization" header value (e.g.
    // "Bearer eyJ..."), so it's rejected by every service's JwtAuthFilter even though it
    // hasn't naturally expired yet.
    void logout(String authorizationHeader);
}