package com.scaler.harsh.authservice.dto;

import lombok.Getter;
import lombok.Setter;

@Getter @Setter
public class LoginResponseDTO {
    private String token;
    private Integer userId;
    private String username;
    private String email;
}